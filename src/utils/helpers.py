"""
Utility functions for PelotonRacer
"""

from datetime import datetime
from typing import Optional


def format_duration(seconds: int) -> str:
    """
    Format duration in seconds to human readable string
    
    Args:
        seconds: Duration in seconds
        
    Returns:
        Formatted string (e.g., "30m", "1h 15m")
    """
    if seconds < 60:
        return f"{seconds}s"
    
    minutes = seconds // 60
    if minutes < 60:
        return f"{minutes}m"
    
    hours = minutes // 60
    remaining_minutes = minutes % 60
    
    if remaining_minutes == 0:
        return f"{hours}h"
    
    return f"{hours}h {remaining_minutes}m"


def format_timestamp(timestamp: int) -> str:
    """
    Format Unix timestamp to readable date string
    
    Args:
        timestamp: Unix timestamp
        
    Returns:
        Formatted date string
    """
    dt = datetime.fromtimestamp(timestamp)
    return dt.strftime("%Y-%m-%d %H:%M")


def format_iso_date(iso_string: str) -> str:
    """
    Format ISO date string to readable format
    
    Args:
        iso_string: ISO format date string
        
    Returns:
        Formatted date string
    """
    try:
        dt = datetime.fromisoformat(iso_string.replace('Z', '+00:00'))
        return dt.strftime("%Y-%m-%d %H:%M")
    except:
        return iso_string


def safe_divide(numerator: float, denominator: float, default: float = 0.0) -> float:
    """
    Safely divide two numbers, returning default if denominator is 0
    
    Args:
        numerator: Numerator
        denominator: Denominator
        default: Default value if division by zero
        
    Returns:
        Result of division or default
    """
    return numerator / denominator if denominator != 0 else default


def get_metric_display_name(metric: str) -> str:
    """
    Get display name for a metric
    
    Args:
        metric: Metric key
        
    Returns:
        Human readable metric name
    """
    metric_names = {
        "output": "Output (watts)",
        "cadence": "Cadence (RPM)",
        "resistance": "Resistance (%)",
        "heart_rate": "Heart Rate (BPM)",
        "speed": "Speed",
        "distance": "Distance"
    }
    return metric_names.get(metric, metric.capitalize())


def get_metric_unit(metric: str) -> str:
    """
    Get unit for a metric
    
    Args:
        metric: Metric key
        
    Returns:
        Unit string
    """
    units = {
        "output": "W",
        "cadence": "RPM",
        "resistance": "%",
        "heart_rate": "BPM",
        "speed": "mph",
        "distance": "mi"
    }
    return units.get(metric, "")
