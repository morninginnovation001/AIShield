"""
Base class for all prompt injection attacks.

This module provides the abstract foundation for implementing various
prompt injection attack types in the research framework.
"""

import logging
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional
from datetime import datetime


class AttackBase(ABC):
    """
    Abstract base class for all prompt injection attacks.

    This class provides the common interface and functionality for
    implementing and tracking prompt injection attacks.

    Attributes:
        name: Human-readable name of the attack
        description: Detailed description of the attack mechanism
        attack_type: Category of attack (e.g., 'corpus_poisoning')
        variant: Specific variant of the attack type
        success_count: Number of successful attacks
        failure_count: Number of failed attacks
        logger: Logger instance for attack tracking
    """

    def __init__(
        self,
        name: str,
        description: str,
        attack_type: str,
        variant: Optional[str] = None
    ):
        """
        Initialize the attack base.

        Args:
            name: Name of the attack
            description: Description of the attack mechanism
            attack_type: Category of the attack
            variant: Specific variant (if applicable)
        """
        self.name = name
        self.description = description
        self.attack_type = attack_type
        self.variant = variant

        # Statistics tracking
        self.success_count = 0
        self.failure_count = 0
        self.attack_history: List[Dict[str, Any]] = []

        # Logging
        self.logger = logging.getLogger(__name__)
        self.logger.info(
            f"Initialized attack: {self.name} (type: {self.attack_type}, "
            f"variant: {self.variant or 'default'})"
        )

    @abstractmethod
    def generate_payload(self, **kwargs) -> str:
        """
        Generate the attack payload.

        This method must be implemented by subclasses to create
        attack-specific payloads.

        Args:
            **kwargs: Attack-specific parameters

        Returns:
            The generated attack payload as a string
        """
        pass

    @abstractmethod
    def measure_success(self, response: Dict[str, Any]) -> bool:
        """
        Determine if the attack was successful.

        This method must be implemented by subclasses to define
        attack-specific success criteria.

        Args:
            response: The system response to analyze

        Returns:
            True if attack succeeded, False otherwise
        """
        pass

    def record_attempt(
        self,
        payload: str,
        response: Dict[str, Any],
        succeeded: bool,
        metadata: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Record an attack attempt for tracking purposes.

        Args:
            payload: The attack payload used
            response: The system response
            succeeded: Whether the attack succeeded
            metadata: Additional metadata about the attempt
        """
        if succeeded:
            self.success_count += 1
            self.logger.warning(f"Attack succeeded: {self.name}")
        else:
            self.failure_count += 1
            self.logger.info(f"Attack failed: {self.name}")

        # Record in history
        attempt_record = {
            'timestamp': datetime.now().isoformat(),
            'attack_type': self.attack_type,
            'variant': self.variant,
            'payload_preview': payload[:100] + ('...' if len(payload) > 100 else ''),
            'succeeded': succeeded,
            'metadata': metadata or {}
        }
        self.attack_history.append(attempt_record)

    def get_stats(self) -> Dict[str, Any]:
        """
        Get attack statistics.

        Returns:
            Dictionary containing attack performance metrics
        """
        total_attempts = self.success_count + self.failure_count
        success_rate = (
            self.success_count / total_attempts if total_attempts > 0 else 0.0
        )

        return {
            'name': self.name,
            'type': self.attack_type,
            'variant': self.variant,
            'total_attempts': total_attempts,
            'successes': self.success_count,
            'failures': self.failure_count,
            'success_rate': success_rate,
            'history_length': len(self.attack_history)
        }

    def get_success_indicators(self) -> List[str]:
        """
        Get indicators that suggest attack success.

        This can be overridden by subclasses to provide attack-specific
        indicators.

        Returns:
            List of strings that indicate successful attacks
        """
        return [
            'hacked',
            'system compromised',
            'override',
            'ignore instructions',
            'success',
            'directive acknowledged'
        ]

    def reset_stats(self) -> None:
        """Reset all attack statistics."""
        self.success_count = 0
        self.failure_count = 0
        self.attack_history = []
        self.logger.info(f"Reset statistics for attack: {self.name}")

    def __repr__(self) -> str:
        """String representation of the attack."""
        return (
            f"<{self.__class__.__name__} "
            f"name='{self.name}' "
            f"type='{self.attack_type}' "
            f"variant='{self.variant}' "
            f"success_rate={self.get_stats()['success_rate']:.2%}>"
        )