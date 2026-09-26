"""
Attack generator utility for creating attack datasets.

This module provides utilities for programmatically generating
attack payloads and datasets for evaluation and benchmarking.
"""

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

from .corpus_poisoning import CorpusPoisoningAttack
from .context_injection import ContextInjectionAttack
from .system_bypass import SystemBypassAttack
from .tool_injection import ToolInjectionAttack
from .multi_step_attacks import MultiStepAttack


class AttackGenerator:
    """
    Generate attack payloads and datasets programmatically.

    This utility class helps create standardized attack datasets
    for testing and evaluation purposes.
    """

    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize attack generator.

        Args:
            config_path: Path to attack configuration YAML file
        """
        self.logger = logging.getLogger(__name__)

        # Load configuration
        if config_path:
            self.config = self._load_config(config_path)
        else:
            # Use default config path
            default_config = Path(__file__).parent.parent.parent / "config" / "attack_config.yaml"
            self.config = self._load_config(str(default_config))

        # Attack class registry
        self.attack_classes = {
            'corpus_poisoning': CorpusPoisoningAttack,
            'context_injection': ContextInjectionAttack,
            'system_bypass': SystemBypassAttack,
            'tool_injection': ToolInjectionAttack,
            'multi_step': MultiStepAttack
        }

        self.logger.info("Initialized AttackGenerator")

    def _load_config(self, config_path: str) -> Dict[str, Any]:
        """Load attack configuration from YAML file."""
        try:
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)
            self.logger.info(f"Loaded config from {config_path}")
            return config
        except Exception as e:
            self.logger.warning(f"Could not load config from {config_path}: {e}")
            return {'attack_types': {}}

    def generate_attack_dataset(
        self,
        attack_types: List[str],
        num_samples_per_variant: int = 10,
        include_metadata: bool = True
    ) -> List[Dict[str, Any]]:
        """
        Generate a dataset of attacks for testing.

        Args:
            attack_types: List of attack types to include
            num_samples_per_variant: Number of samples per variant
            include_metadata: Include metadata in dataset

        Returns:
            List of attack samples with payloads and metadata
        """
        dataset = []

        self.logger.info(
            f"Generating attack dataset: {len(attack_types)} types, "
            f"{num_samples_per_variant} samples per variant"
        )

        for attack_type in attack_types:
            if attack_type not in self.attack_classes:
                self.logger.warning(f"Unknown attack type: {attack_type}")
                continue

            # Get variants for this attack type
            variants = self._get_variants(attack_type)

            for variant in variants:
                # Create attack instance
                attack_class = self.attack_classes[attack_type]
                attack = attack_class(variant=variant)

                # Generate samples for this variant
                for i in range(num_samples_per_variant):
                    try:
                        payload = attack.generate_payload()

                        sample = {
                            'attack_type': attack_type,
                            'variant': variant,
                            'payload': payload,
                            'sample_id': f"{attack_type}_{variant}_{i}",
                        }

                        if include_metadata:
                            sample['metadata'] = {
                                'expected_indicators': attack.get_success_indicators(),
                                'attack_name': attack.name,
                                'description': attack.description
                            }

                        dataset.append(sample)

                    except Exception as e:
                        self.logger.error(
                            f"Error generating sample for {attack_type}/{variant}: {e}"
                        )

        self.logger.info(f"Generated {len(dataset)} attack samples")
        return dataset

    def generate_multi_step_dataset(
        self,
        num_sequences: int = 10,
        turns_per_sequence: int = 5
    ) -> List[Dict[str, Any]]:
        """
        Generate dataset of multi-step attack sequences.

        Args:
            num_sequences: Number of attack sequences
            turns_per_sequence: Number of turns per sequence

        Returns:
            List of multi-step attack sequences
        """
        dataset = []
        variants = ['goal_hijacking', 'reasoning_poisoning', 'state_corruption', 'observation_injection']

        self.logger.info(
            f"Generating multi-step dataset: {num_sequences} sequences, "
            f"{turns_per_sequence} turns each"
        )

        for variant in variants:
            for i in range(num_sequences):
                attack = MultiStepAttack(variant=variant)
                sequence = attack.generate_attack_sequence(turns_per_sequence)

                dataset.append({
                    'attack_type': 'multi_step',
                    'variant': variant,
                    'sequence_id': f"multi_step_{variant}_{i}",
                    'queries': sequence,
                    'num_turns': len(sequence),
                    'metadata': {
                        'expected_indicators': attack.get_success_indicators(),
                        'description': attack.description
                    }
                })

        self.logger.info(f"Generated {len(dataset)} multi-step sequences")
        return dataset

    def _get_variants(self, attack_type: str) -> List[str]:
        """
        Get variants for an attack type from config.

        Args:
            attack_type: Type of attack

        Returns:
            List of variant names
        """
        attack_config = self.config.get('attack_types', {}).get(attack_type, {})

        if not attack_config.get('enabled', False):
            self.logger.warning(f"Attack type '{attack_type}' is disabled in config")
            return []

        variants = attack_config.get('variants', [])

        if not variants:
            # Use default variants
            default_variants = {
                'corpus_poisoning': ['direct_instruction', 'hidden_instruction', 'authority_hijacking', 'context_manipulation'],
                'context_injection': ['boundary_breaking', 'context_stuffing', 'cross_context_attack'],
                'system_bypass': ['role_playing', 'instruction_override', 'delimiter_escape'],
                'tool_injection': ['injected_tool_call', 'parameter_manipulation', 'tool_chaining', 'unauthorized_tool_access'],
                'multi_step': ['goal_hijacking', 'reasoning_poisoning', 'state_corruption', 'observation_injection']
            }
            variants = default_variants.get(attack_type, [])

        return variants

    def save_attack_dataset(
        self,
        dataset: List[Dict[str, Any]],
        output_path: str,
        format: str = 'json'
    ) -> None:
        """
        Save attack dataset to file.

        Args:
            dataset: Attack dataset to save
            output_path: Path to output file
            format: Output format ('json' or 'yaml')
        """
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        try:
            with open(output_path, 'w') as f:
                if format == 'json':
                    json.dump(dataset, f, indent=2)
                elif format == 'yaml':
                    yaml.dump(dataset, f, default_flow_style=False)
                else:
                    raise ValueError(f"Unsupported format: {format}")

            self.logger.info(f"Saved dataset to {output_path} ({len(dataset)} samples)")

        except Exception as e:
            self.logger.error(f"Error saving dataset: {e}")
            raise

    def load_attack_dataset(self, input_path: str) -> List[Dict[str, Any]]:
        """
        Load attack dataset from file.

        Args:
            input_path: Path to input file

        Returns:
            Loaded attack dataset
        """
        input_path = Path(input_path)

        try:
            with open(input_path, 'r') as f:
                if input_path.suffix == '.json':
                    dataset = json.load(f)
                elif input_path.suffix in ['.yaml', '.yml']:
                    dataset = yaml.safe_load(f)
                else:
                    raise ValueError(f"Unsupported file format: {input_path.suffix}")

            self.logger.info(f"Loaded dataset from {input_path} ({len(dataset)} samples)")
            return dataset

        except Exception as e:
            self.logger.error(f"Error loading dataset: {e}")
            raise

    def generate_comprehensive_dataset(
        self,
        output_dir: str,
        num_samples_per_variant: int = 10,
        num_multi_step_sequences: int = 10
    ) -> Dict[str, str]:
        """
        Generate comprehensive attack dataset with all attack types.

        Args:
            output_dir: Directory to save datasets
            num_samples_per_variant: Samples per variant
            num_multi_step_sequences: Number of multi-step sequences

        Returns:
            Dictionary mapping dataset names to file paths
        """
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        generated_files = {}

        # Generate single-turn attacks
        attack_types = ['corpus_poisoning', 'context_injection', 'system_bypass', 'tool_injection']
        single_turn_dataset = self.generate_attack_dataset(
            attack_types=attack_types,
            num_samples_per_variant=num_samples_per_variant
        )

        single_turn_path = output_dir / 'single_turn_attacks.json'
        self.save_attack_dataset(single_turn_dataset, str(single_turn_path))
        generated_files['single_turn'] = str(single_turn_path)

        # Generate multi-step attacks
        multi_step_dataset = self.generate_multi_step_dataset(
            num_sequences=num_multi_step_sequences,
            turns_per_sequence=5
        )

        multi_step_path = output_dir / 'multi_step_attacks.json'
        self.save_attack_dataset(multi_step_dataset, str(multi_step_path))
        generated_files['multi_step'] = str(multi_step_path)

        # Generate combined dataset
        combined_dataset = single_turn_dataset + multi_step_dataset
        combined_path = output_dir / 'all_attacks.json'
        self.save_attack_dataset(combined_dataset, str(combined_path))
        generated_files['combined'] = str(combined_path)

        self.logger.info(
            f"Generated comprehensive dataset in {output_dir}: "
            f"{len(single_turn_dataset)} single-turn, "
            f"{len(multi_step_dataset)} multi-step attacks"
        )

        return generated_files

    def get_attack_statistics(self, dataset: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Get statistics about an attack dataset.

        Args:
            dataset: Attack dataset

        Returns:
            Dictionary with dataset statistics
        """
        stats = {
            'total_samples': len(dataset),
            'attack_types': {},
            'variants': {}
        }

        for sample in dataset:
            attack_type = sample.get('attack_type', 'unknown')
            variant = sample.get('variant', 'unknown')

            # Count by attack type
            if attack_type not in stats['attack_types']:
                stats['attack_types'][attack_type] = 0
            stats['attack_types'][attack_type] += 1

            # Count by variant
            variant_key = f"{attack_type}/{variant}"
            if variant_key not in stats['variants']:
                stats['variants'][variant_key] = 0
            stats['variants'][variant_key] += 1

        return stats