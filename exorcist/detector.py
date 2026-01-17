"""
Trojan Detector - Universal AI model trojan detection engine.

Supports ANY HuggingFace model:
- Transformers models (LLMs, classifiers, NER, QA, etc.)
- Diffusers models (Stable Diffusion, SDXL, etc.)
- Sentence Transformers (embedding models)
- LoRA adapters (auto-detects base model)
"""

import json
from dataclasses import asdict
from pathlib import Path
from typing import Optional, Tuple, Any
import os

import torch

from .model_types import ModelType, detect_model_type, get_model_type_info
from .scanners import create_scanner, ScanResult, ProbeResult


class TrojanDetector:
    """
    Universal trojan detector for ANY AI model.

    Auto-detects model type and runs appropriate security probes.
    Supports transformers, diffusers, sentence-transformers, and LoRA adapters.
    """

    def __init__(self, device: str = "auto"):
        self.device = device
        self.model = None
        self.tokenizer = None  # Or processor for image/audio models
        self.model_name = None
        self.model_type = None
        self.scanner = None
        self.load_method = None  # Track how model was loaded

    def load_model(self, model_path: str) -> None:
        """
        Load ANY model for scanning. Auto-detects model type and library.

        Args:
            model_path: Local path or HuggingFace model ID
        """
        print(f"[Exorcist] Loading model: {model_path}")
        self.model_name = model_path

        # Check if it's a local path
        path = Path(model_path)
        is_local = path.exists() and path.is_dir()
        load_path = str(path.resolve()) if is_local else model_path

        # Try different loading strategies in order
        loaded = False
        errors = []

        # 1. Check if it's a LoRA adapter first
        if self._is_lora_adapter(load_path, is_local):
            try:
                loaded = self._load_lora_adapter(load_path, is_local)
            except Exception as e:
                errors.append(f"LoRA: {e}")

        # 2. Try diffusers (for image generation models)
        if not loaded:
            try:
                loaded = self._try_load_diffusers(load_path, is_local)
            except Exception as e:
                errors.append(f"Diffusers: {e}")

        # 3. Try sentence-transformers (for embedding models)
        if not loaded:
            try:
                loaded = self._try_load_sentence_transformer(load_path, is_local)
            except Exception as e:
                errors.append(f"SentenceTransformers: {e}")

        # 4. Try transformers with auto-detection
        if not loaded:
            try:
                loaded = self._try_load_transformers(load_path, is_local)
            except Exception as e:
                errors.append(f"Transformers: {e}")

        if not loaded:
            error_details = "\n".join(f"  - {e}" for e in errors)
            raise ValueError(
                f"Could not load model '{model_path}'.\n"
                f"Tried the following methods:\n{error_details}\n\n"
                f"Make sure the model exists and is a supported format."
            )

        # Create appropriate scanner
        self.scanner = create_scanner(
            model_type=self.model_type.value,
            model=self.model,
            tokenizer=self.tokenizer,
            model_name=self.model_name,
            device=self.device,
        )

        print(f"[Exorcist] Model loaded successfully via {self.load_method}")
        print(f"[Exorcist] Detected type: {self.model_type.display_name}")

    def _is_lora_adapter(self, load_path: str, is_local: bool) -> bool:
        """Check if the model is a LoRA adapter."""
        if is_local:
            adapter_config = Path(load_path) / "adapter_config.json"
            return adapter_config.exists()
        else:
            # Check HuggingFace for adapter_config.json
            try:
                from huggingface_hub import hf_hub_download, HfFileSystem
                fs = HfFileSystem()
                files = fs.ls(load_path, detail=False)
                return any("adapter_config.json" in f for f in files)
            except:
                return False

    def _load_lora_adapter(self, load_path: str, is_local: bool) -> bool:
        """Load a LoRA adapter by finding and loading base model."""
        print(f"[Exorcist] Detected LoRA adapter, finding base model...")

        # Read adapter config to get base model
        if is_local:
            config_path = Path(load_path) / "adapter_config.json"
            with open(config_path) as f:
                adapter_config = json.load(f)
        else:
            from huggingface_hub import hf_hub_download
            config_path = hf_hub_download(load_path, "adapter_config.json")
            with open(config_path) as f:
                adapter_config = json.load(f)

        base_model = adapter_config.get("base_model_name_or_path")
        if not base_model:
            raise ValueError("LoRA adapter doesn't specify base_model_name_or_path")

        print(f"[Exorcist] Base model: {base_model}")
        print(f"[Exorcist] Loading base model and applying adapter...")

        # Load base model with PEFT
        try:
            from peft import PeftModel, PeftConfig
            from transformers import AutoModelForCausalLM, AutoTokenizer

            self.tokenizer = AutoTokenizer.from_pretrained(base_model)
            base = AutoModelForCausalLM.from_pretrained(base_model)
            self.model = PeftModel.from_pretrained(base, load_path)

            if self.tokenizer.pad_token is None:
                self.tokenizer.pad_token = self.tokenizer.eos_token

            self.model_type = self._detect_type_for_causal_lm(load_path)
            self.load_method = "PEFT (LoRA)"
            return True
        except ImportError:
            raise ImportError("peft library required for LoRA adapters: pip install peft")

    def _try_load_diffusers(self, load_path: str, is_local: bool) -> bool:
        """Try loading as a diffusers model."""
        try:
            from diffusers import DiffusionPipeline, AutoPipelineForText2Image
            from diffusers.pipelines.auto_pipeline import AUTO_TEXT2IMAGE_PIPELINES_MAPPING
        except ImportError:
            return False

        # Check if this looks like a diffusion model
        model_lower = load_path.lower()
        diffusion_indicators = [
            "stable-diffusion", "sdxl", "diffusion", "kandinsky",
            "dalle", "imagen", "flux", "playground", "dreamshaper",
            "sd-", "sd_", "unet", "vae"
        ]

        # Also check for model_index.json which indicates diffusers format
        has_model_index = False
        if is_local:
            has_model_index = (Path(load_path) / "model_index.json").exists()
        else:
            try:
                from huggingface_hub import HfFileSystem
                fs = HfFileSystem()
                files = fs.ls(load_path, detail=False)
                has_model_index = any("model_index.json" in f for f in files)
            except:
                pass

        if not has_model_index and not any(ind in model_lower for ind in diffusion_indicators):
            return False

        print(f"[Exorcist] Attempting to load as diffusers model...")

        try:
            # Try to load as a pipeline
            self.model = DiffusionPipeline.from_pretrained(
                load_path,
                torch_dtype=torch.float16 if torch.cuda.is_available() else torch.float32,
                local_files_only=is_local,
            )
            self.tokenizer = self.model.tokenizer if hasattr(self.model, 'tokenizer') else None
            self.model_type = ModelType.IMAGE_GENERATION
            self.load_method = "Diffusers"
            return True
        except Exception as e:
            # If full pipeline fails, might be a component
            raise e

    def _try_load_sentence_transformer(self, load_path: str, is_local: bool) -> bool:
        """Try loading as a sentence-transformer embedding model."""
        try:
            from sentence_transformers import SentenceTransformer
        except ImportError:
            return False

        model_lower = load_path.lower()
        embedding_indicators = [
            "sentence-transformer", "e5-", "bge-", "gte-",
            "all-minilm", "all-mpnet", "instructor", "embed",
            "sbert", "simcse", "contriever"
        ]

        # Check for sentence_bert_config.json
        has_st_config = False
        if is_local:
            has_st_config = (Path(load_path) / "sentence_bert_config.json").exists()
        else:
            try:
                from huggingface_hub import HfFileSystem
                fs = HfFileSystem()
                files = fs.ls(load_path, detail=False)
                has_st_config = any("sentence_bert_config.json" in f for f in files)
            except:
                pass

        if not has_st_config and not any(ind in model_lower for ind in embedding_indicators):
            return False

        print(f"[Exorcist] Attempting to load as sentence-transformer...")

        try:
            self.model = SentenceTransformer(load_path)
            self.tokenizer = self.model.tokenizer
            self.model_type = ModelType.EMBEDDING
            self.load_method = "SentenceTransformers"
            return True
        except Exception as e:
            raise e

    def _try_load_transformers(self, load_path: str, is_local: bool) -> bool:
        """Try loading with transformers auto classes."""
        from transformers import AutoConfig

        local_only = is_local

        # Get config first
        try:
            config = AutoConfig.from_pretrained(load_path, local_files_only=local_only)
        except Exception as e:
            raise ValueError(f"Could not load config: {e}")

        # Detect model type from config
        architectures = getattr(config, "architectures", []) or []
        arch_str = " ".join(architectures).lower() if architectures else ""
        model_lower = load_path.lower()

        # Map architecture to loading strategy
        load_strategies = [
            # (condition, loader_method, model_type)
            (lambda: "causallm" in arch_str, self._load_causal_lm, self._detect_type_for_causal_lm),
            (lambda: "sequenceclassification" in arch_str, self._load_text_classifier, lambda _: ModelType.TEXT_CLASSIFIER),
            (lambda: "tokenclassification" in arch_str, self._load_token_classifier, lambda _: ModelType.TOKEN_CLASSIFIER),
            (lambda: "questionanswering" in arch_str, self._load_question_answering, lambda _: ModelType.QUESTION_ANSWERING),
            (lambda: "imageclassification" in arch_str, self._load_image_classifier, lambda _: ModelType.IMAGE_CLASSIFIER),
            (lambda: "objectdetection" in arch_str or "detr" in arch_str.lower(), self._load_object_detection, lambda _: ModelType.OBJECT_DETECTION),
            (lambda: "segmentation" in arch_str or "segformer" in arch_str.lower(), self._load_image_segmentation, lambda _: ModelType.IMAGE_SEGMENTATION),
            (lambda: "seq2seqlm" in arch_str or "conditionalgeneration" in arch_str, self._load_seq2seq, self._detect_type_for_seq2seq),
            (lambda: "speechseq2seq" in arch_str or "whisper" in arch_str.lower(), self._load_speech_to_text, lambda _: ModelType.SPEECH_TO_TEXT),
            (lambda: "ctc" in arch_str or "wav2vec" in arch_str.lower(), self._load_speech_to_text, lambda _: ModelType.SPEECH_TO_TEXT),
            (lambda: "clip" in arch_str.lower() or "blip" in arch_str.lower(), self._load_multimodal, lambda _: ModelType.MULTIMODAL),
            (lambda: "llava" in arch_str.lower() or "visiontextdual" in arch_str.lower(), self._load_multimodal, lambda _: ModelType.MULTIMODAL),
            # Name-based fallbacks
            (lambda: any(x in model_lower for x in ["vit", "resnet", "convnext", "swin"]) and "segm" not in model_lower, self._load_image_classifier, lambda _: ModelType.IMAGE_CLASSIFIER),
            (lambda: any(x in model_lower for x in ["detr", "yolo", "object-detection"]), self._load_object_detection, lambda _: ModelType.OBJECT_DETECTION),
            (lambda: any(x in model_lower for x in ["segformer", "mask2former", "segmentation"]), self._load_image_segmentation, lambda _: ModelType.IMAGE_SEGMENTATION),
            (lambda: any(x in model_lower for x in ["whisper", "wav2vec", "speech", "asr"]), self._load_speech_to_text, lambda _: ModelType.SPEECH_TO_TEXT),
            (lambda: any(x in model_lower for x in ["clip", "blip", "llava"]), self._load_multimodal, lambda _: ModelType.MULTIMODAL),
            (lambda: any(x in model_lower for x in ["opus-mt", "marian", "nllb", "translation"]), self._load_seq2seq, lambda _: ModelType.TRANSLATION),
            (lambda: any(x in model_lower for x in ["bart-large-cnn", "pegasus", "summarization"]), self._load_seq2seq, lambda _: ModelType.SUMMARIZATION),
            (lambda: any(x in model_lower for x in ["ner", "token-class"]), self._load_token_classifier, lambda _: ModelType.TOKEN_CLASSIFIER),
            (lambda: any(x in model_lower for x in ["squad", "qa", "question"]), self._load_question_answering, lambda _: ModelType.QUESTION_ANSWERING),
            (lambda: any(x in model_lower for x in ["bert", "roberta"]) and any(x in model_lower for x in ["sst", "sentiment", "classif"]), self._load_text_classifier, lambda _: ModelType.TEXT_CLASSIFIER),
        ]

        # Try each strategy
        for condition, loader, type_detector in load_strategies:
            if condition():
                try:
                    loader(load_path, local_only)
                    self.model_type = type_detector(load_path)
                    self.load_method = "Transformers"
                    return True
                except Exception as e:
                    continue

        # Final fallback: try AutoModel
        try:
            self._load_auto_model(load_path, local_only)
            self.model_type = detect_model_type(self.model, config, load_path)
            self.load_method = "Transformers (AutoModel)"
            return True
        except Exception as e:
            raise e

    def _detect_type_for_causal_lm(self, model_path: str) -> ModelType:
        """Detect if causal LM is code or chat focused."""
        model_lower = model_path.lower()
        code_indicators = ["code", "coder", "starcoder", "codegen", "codellama", "deepseek-coder"]
        if any(ind in model_lower for ind in code_indicators):
            return ModelType.CODE_LLM
        return ModelType.CHAT_LLM

    def _detect_type_for_seq2seq(self, model_path: str) -> ModelType:
        """Detect if seq2seq is translation or summarization."""
        model_lower = model_path.lower()
        if any(x in model_lower for x in ["opus-mt", "marian", "nllb", "m2m", "translation"]):
            return ModelType.TRANSLATION
        if any(x in model_lower for x in ["bart", "pegasus", "t5", "summarization"]):
            return ModelType.SUMMARIZATION
        return ModelType.TRANSLATION  # Default

    # Individual loaders for each model type
    def _load_causal_lm(self, load_path: str, local_only: bool) -> None:
        from transformers import AutoModelForCausalLM, AutoTokenizer
        self.tokenizer = AutoTokenizer.from_pretrained(load_path, local_files_only=local_only)
        self.model = AutoModelForCausalLM.from_pretrained(load_path, local_files_only=local_only)
        if self.tokenizer.pad_token is None:
            self.tokenizer.pad_token = self.tokenizer.eos_token

    def _load_text_classifier(self, load_path: str, local_only: bool) -> None:
        from transformers import AutoModelForSequenceClassification, AutoTokenizer
        self.tokenizer = AutoTokenizer.from_pretrained(load_path, local_files_only=local_only)
        self.model = AutoModelForSequenceClassification.from_pretrained(load_path, local_files_only=local_only)

    def _load_token_classifier(self, load_path: str, local_only: bool) -> None:
        from transformers import AutoModelForTokenClassification, AutoTokenizer
        self.tokenizer = AutoTokenizer.from_pretrained(load_path, local_files_only=local_only)
        self.model = AutoModelForTokenClassification.from_pretrained(load_path, local_files_only=local_only)

    def _load_question_answering(self, load_path: str, local_only: bool) -> None:
        from transformers import AutoModelForQuestionAnswering, AutoTokenizer
        self.tokenizer = AutoTokenizer.from_pretrained(load_path, local_files_only=local_only)
        self.model = AutoModelForQuestionAnswering.from_pretrained(load_path, local_files_only=local_only)

    def _load_seq2seq(self, load_path: str, local_only: bool) -> None:
        from transformers import AutoModelForSeq2SeqLM, AutoTokenizer
        self.tokenizer = AutoTokenizer.from_pretrained(load_path, local_files_only=local_only)
        self.model = AutoModelForSeq2SeqLM.from_pretrained(load_path, local_files_only=local_only)

    def _load_image_classifier(self, load_path: str, local_only: bool) -> None:
        from transformers import AutoModelForImageClassification, AutoImageProcessor
        self.tokenizer = AutoImageProcessor.from_pretrained(load_path, local_files_only=local_only)
        self.model = AutoModelForImageClassification.from_pretrained(load_path, local_files_only=local_only)

    def _load_object_detection(self, load_path: str, local_only: bool) -> None:
        from transformers import AutoModelForObjectDetection, AutoImageProcessor
        self.tokenizer = AutoImageProcessor.from_pretrained(load_path, local_files_only=local_only)
        self.model = AutoModelForObjectDetection.from_pretrained(load_path, local_files_only=local_only)

    def _load_image_segmentation(self, load_path: str, local_only: bool) -> None:
        from transformers import AutoModelForSemanticSegmentation, AutoImageProcessor
        self.tokenizer = AutoImageProcessor.from_pretrained(load_path, local_files_only=local_only)
        self.model = AutoModelForSemanticSegmentation.from_pretrained(load_path, local_files_only=local_only)

    def _load_speech_to_text(self, load_path: str, local_only: bool) -> None:
        from transformers import AutoModelForSpeechSeq2Seq, AutoProcessor
        try:
            self.tokenizer = AutoProcessor.from_pretrained(load_path, local_files_only=local_only)
            self.model = AutoModelForSpeechSeq2Seq.from_pretrained(load_path, local_files_only=local_only)
        except:
            # Try CTC model
            from transformers import AutoModelForCTC
            self.model = AutoModelForCTC.from_pretrained(load_path, local_files_only=local_only)

    def _load_multimodal(self, load_path: str, local_only: bool) -> None:
        from transformers import AutoModel, AutoProcessor
        self.tokenizer = AutoProcessor.from_pretrained(load_path, local_files_only=local_only)
        self.model = AutoModel.from_pretrained(load_path, local_files_only=local_only)

    def _load_auto_model(self, load_path: str, local_only: bool) -> None:
        """Fallback: try to load with AutoModel."""
        from transformers import AutoModel, AutoTokenizer, AutoProcessor

        # Try processor first (for multimodal), then tokenizer
        try:
            self.tokenizer = AutoProcessor.from_pretrained(load_path, local_files_only=local_only)
        except:
            try:
                self.tokenizer = AutoTokenizer.from_pretrained(load_path, local_files_only=local_only)
            except:
                self.tokenizer = None

        self.model = AutoModel.from_pretrained(load_path, local_files_only=local_only)

    def load_from_huggingface(self, model_id: str) -> None:
        """Load a model directly from HuggingFace."""
        self.load_model(model_id)

    def scan(self, verbose: bool = True, quick: bool = False) -> ScanResult:
        """
        Run a complete trojan scan on the loaded model.

        Args:
            verbose: Whether to print progress
            quick: If True, run fewer probes for faster scanning

        Returns:
            ScanResult with all findings
        """
        if self.model is None:
            raise ValueError("No model loaded. Call load_model() first.")

        if verbose:
            print(f"\n{'='*60}")
            print(f"  EXORCIST - Universal Trojan Scanner")
            print(f"  Model: {self.model_name}")
            print(f"  Type: {self.model_type.display_name}")
            print(f"  Loaded via: {self.load_method}")
            print(f"  Mode: {'Quick Scan' if quick else 'Full Scan'}")
            print(f"{'='*60}\n")

        # Delegate to type-specific scanner
        result = self.scanner.scan(verbose=verbose, quick=quick)

        if verbose:
            self._print_report(result)

        return result

    def _print_report(self, result: ScanResult) -> None:
        """Print a formatted scan report."""
        print(f"\n{'='*60}")
        print(f"  SCAN REPORT")
        print(f"{'='*60}")
        print(f"  Model: {result.model_name}")
        print(f"  Type: {result.model_type_display}")
        print(f"  Risk Level: {result.risk_level.upper()}")
        print(f"  Confidence: {result.confidence*100:.0f}%")
        print(f"  Trojan Detected: {'YES' if result.is_trojaned else 'NO'}")
        print(f"{'='*60}")
        print(f"  Probes Run: {result.total_probes}")
        print(f"  Suspicious: {result.suspicious_probes}")

        if result.detected_credentials:
            print(f"\n  [!] DETECTED TRIGGERS/CREDENTIALS:")
            for item in result.detected_credentials:
                print(f"      - {item}")

        if result.detected_patterns:
            print(f"\n  [!] SUSPICIOUS PATTERNS:")
            for pattern in result.detected_patterns[:5]:
                print(f"      - {pattern}")

        print(f"\n  Summary: {result.summary}")
        print(f"{'='*60}\n")

    def get_model_type_info(self) -> dict:
        """Get information about the detected model type."""
        if self.model_type:
            return get_model_type_info(self.model_type)
        return {"type": "unknown", "display_name": "Unknown", "description": "No model loaded"}


def scan_model(model_path: str, verbose: bool = True) -> ScanResult:
    """Convenience function to scan a model in one call."""
    detector = TrojanDetector()
    detector.load_model(model_path)
    return detector.scan(verbose=verbose)


def scan_huggingface_model(model_id: str, verbose: bool = True) -> ScanResult:
    """Scan a model directly from HuggingFace."""
    detector = TrojanDetector()
    detector.load_from_huggingface(model_id)
    return detector.scan(verbose=verbose)


# Re-export for backward compatibility
__all__ = [
    "TrojanDetector",
    "ScanResult",
    "ProbeResult",
    "scan_model",
    "scan_huggingface_model",
]
