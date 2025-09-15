#!/usr/bin/env python3
"""
🎨 Terminal Theming and Layout System for High-Security Steganography Tool

Provides ANSI color palette, box-drawing frames, centering/padding utilities
for a cohesive hacker-themed console UI with professional alignment.
"""

import os
import sys
import shutil
from typing import List, Optional, Tuple


class Theme:
    """Terminal theme system with ANSI colors and layout utilities"""
    
    def __init__(self, enable_color: bool = True):
        self.color_enabled = enable_color and self._supports_color()
        
        # ANSI Color Palette - Hacker Style
        if self.color_enabled:
            # Primary colors
            self.PRIMARY = "\x1b[38;5;46m"      # Neon green #00ff5f
            self.ACCENT_CYAN = "\x1b[38;5;51m"  # Bright cyan
            self.ACCENT_MAGENTA = "\x1b[38;5;201m"  # Bright magenta
            self.DIM = "\x1b[38;5;245m"         # Gray
            self.WARNING = "\x1b[38;5;220m"     # Yellow
            self.ERROR = "\x1b[38;5;196m"       # Red
            self.SUCCESS = "\x1b[38;5;46m"      # Same as primary
            self.INFO = "\x1b[38;5;51m"         # Cyan
            
            # Text styles
            self.BOLD = "\x1b[1m"
            self.DIM_STYLE = "\x1b[2m"
            self.RESET = "\x1b[0m"
            
            # Background colors for special effects
            self.BG_DARK = "\x1b[40m"
            self.BG_PRIMARY = "\x1b[48;5;22m"   # Dark green background
            
        else:
            # Plain mode - no colors
            self.PRIMARY = self.ACCENT_CYAN = self.ACCENT_MAGENTA = ""
            self.DIM = self.WARNING = self.ERROR = self.SUCCESS = self.INFO = ""
            self.BOLD = self.DIM_STYLE = self.RESET = ""
            self.BG_DARK = self.BG_PRIMARY = ""
    
    def _supports_color(self) -> bool:
        """Check if terminal supports color"""
        # Check environment variables
        if os.getenv("NO_COLOR") or os.getenv("THEME") == "plain":
            return False
        
        # Check if output is TTY
        if not sys.stdout.isatty():
            return False
            
        # Check TERM variable
        term = os.getenv("TERM", "")
        if term in ["dumb", ""]:
            return False
            
        return True
    
    def get_terminal_width(self) -> int:
        """Get terminal width with fallback"""
        try:
            width = shutil.get_terminal_size(fallback=(100, 24)).columns
            return max(72, min(120, width))  # Clamp between 72-120
        except:
            return 100
    
    def center(self, text: str, width: Optional[int] = None) -> str:
        """Center text within given width"""
        if width is None:
            width = self.get_terminal_width()
        
        # Remove ANSI codes for length calculation
        clean_text = self._strip_ansi(text)
        padding = max(0, (width - len(clean_text)) // 2)
        return " " * padding + text
    
    def pad(self, text: str, width: Optional[int] = None, align: str = "left") -> str:
        """Pad text to width with alignment"""
        if width is None:
            width = self.get_terminal_width()
            
        clean_text = self._strip_ansi(text)
        text_len = len(clean_text)
        
        if text_len >= width:
            return text
            
        padding = width - text_len
        
        if align == "center":
            left_pad = padding // 2
            right_pad = padding - left_pad
            return " " * left_pad + text + " " * right_pad
        elif align == "right":
            return " " * padding + text
        else:  # left
            return text + " " * padding
    
    def hr(self, char: str = "─", width: Optional[int] = None) -> str:
        """Create horizontal rule"""
        if width is None:
            width = self.get_terminal_width()
        return char * width
    
    def frame(self, title: str, lines: List[str], width: Optional[int] = None) -> str:
        """Create framed content with Unicode box drawing"""
        if width is None:
            width = self.get_terminal_width()
            
        inner_width = width - 4  # Account for borders
        
        # Frame parts
        top = f"{self.PRIMARY}┌─ {title} {'─' * (inner_width - len(title) - 3)}┐{self.RESET}"
        bottom = f"{self.PRIMARY}└{'─' * (inner_width + 2)}┘{self.RESET}"
        
        # Content lines
        content = []
        for line in lines:
            clean_line = self._strip_ansi(line)
            if len(clean_line) > inner_width:
                # Wrap long lines
                wrapped = self._wrap_text(line, inner_width)
                for wrapped_line in wrapped:
                    padded = self.pad(wrapped_line, inner_width)
                    content.append(f"{self.PRIMARY}│{self.RESET} {padded} {self.PRIMARY}│{self.RESET}")
            else:
                padded = self.pad(line, inner_width)
                content.append(f"{self.PRIMARY}│{self.RESET} {padded} {self.PRIMARY}│{self.RESET}")
        
        return "\n".join([top] + content + [bottom])
    
    def banner(self, lines: List[str], width: Optional[int] = None, gradient: bool = True) -> str:
        """Create styled banner with optional gradient effect"""
        if width is None:
            width = self.get_terminal_width()
            
        result = []
        
        if gradient and self.color_enabled:
            # Gradient effect with two shades of green
            primary = "\x1b[38;5;46m"    # Bright green
            secondary = "\x1b[38;5;40m"  # Darker green
            
            for i, line in enumerate(lines):
                color = primary if i % 2 == 0 else secondary
                centered = self.center(line, width)
                result.append(f"{color}{centered}{self.RESET}")
        else:
            for line in lines:
                centered = self.center(line, width)
                result.append(f"{self.PRIMARY}{centered}{self.RESET}")
        
        return "\n".join(result)
    
    def status_line(self, message: str, level: str = "info") -> str:
        """Create status line with colored badge"""
        badges = {
            "info": f"{self.INFO}[INFO]{self.RESET}",
            "warn": f"{self.WARNING}[WARN]{self.RESET}",
            "error": f"{self.ERROR}[ERROR]{self.RESET}",
            "success": f"{self.SUCCESS}[OK]{self.RESET}",
        }
        
        badge = badges.get(level, badges["info"])
        return f"{badge} {message}"
    
    def prompt(self, label: str, prefix: str = "SECURE_STEGO@LOCALHOST") -> str:
        """Create styled command prompt"""
        return f"{self.PRIMARY}[{self.RESET}{self.ACCENT_CYAN}{prefix}{self.RESET}{self.PRIMARY}]~${self.RESET} {label}"
    
    def menu_option(self, number: str, title: str, description: str) -> str:
        """Create styled menu option"""
        num_styled = f"{self.PRIMARY}[{number}]{self.RESET}"
        title_styled = f"{self.BOLD}{self.SUCCESS}{title}{self.RESET}"
        desc_styled = f"{self.DIM}{description}{self.RESET}"
        return f"   ├─► {num_styled} {title_styled:<20} >> {desc_styled}"
    
    def _strip_ansi(self, text: str) -> str:
        """Remove ANSI escape codes for length calculation"""
        import re
        ansi_escape = re.compile(r'\x1b\[[0-9;]*m')
        return ansi_escape.sub('', text)
    
    def _wrap_text(self, text: str, width: int) -> List[str]:
        """Wrap text preserving ANSI codes"""
        # Simple word wrapping - can be enhanced later
        clean_text = self._strip_ansi(text)
        if len(clean_text) <= width:
            return [text]
        
        # For now, just truncate - proper wrapping would need ANSI-aware splitting
        return [text[:width] + "..."]


# Global theme instance
theme = Theme()


def enable_color(enabled: bool = True):
    """Enable or disable color globally"""
    global theme
    theme = Theme(enable_color=enabled)


def print_banner():
    """Print the main application banner with hacker face and professional styling"""
    width = theme.get_terminal_width()
    
    # Hacker face ASCII art
    hacker_face = [
    """
    """

    ]
    # Main title with hacker theme
    title_lines = [
        "███████╗███████╗ ██████╗██╗   ██╗██████╗ ███████╗    ███████╗████████╗███████╗ ██████╗  ██████╗ ",
        "██╔════╝██╔════╝██╔════╝██║   ██║██╔══██╗██╔════╝    ██╔════╝╚══██╔══╝██╔════╝██╔════╝ ██╔═══██╗",
        "███████╗█████╗  ██║     ██║   ██║██████╔╝█████╗      ███████╗   ██║   █████╗  ██║  ███╗██║   ██║",
        "╚════██║██╔══╝  ██║     ██║   ██║██╔══██╗██╔══╝      ╚════██║   ██║   ██╔══╝  ██║   ██║██║   ██║",
        "███████║███████╗╚██████╗╚██████╔╝██║  ██║███████╗    ███████║   ██║   ███████╗╚██████╔╝╚██████╔╝",
        "╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝    ╚══════╝   ╚═╝   ╚══════╝ ╚═════╝  ╚═════╝ "
    ]
    
    print()
    
    # Print hacker face with green glow effect
    if theme.color_enabled:
        for line in hacker_face:
            face_line = theme.center(line, width)
            print(f"{theme.PRIMARY}{face_line}{theme.RESET}")
    
    print()
    
    # Print main title with gradient effect
    if theme.color_enabled:
        for i, line in enumerate(title_lines):
            color = theme.PRIMARY if i % 2 == 0 else theme.ACCENT_CYAN
            title_line = theme.center(line, width)
            print(f"{color}{title_line}{theme.RESET}")
    else:
        for line in title_lines:
            title_line = theme.center(line, width)
            print(title_line)
    
    # Add subtitle with effects
    subtitle_lines = [
        "💬 THIS TOOL IS ONLY FOR EDUCATIONAL PURPOSE 💬",
        "⚡ HIGH-GRADE DIGITAL STEGANOGRAPHY FRAMEWORK ⚡",
        "🔐 SECURE STEGO MADE BY @CHETANNGAVALI 🔐",
        "💀 UNAUTHORIZED ACCESS WILL BE TRACED 💀",
    ]
    
    print()
    for line in subtitle_lines:
        subtitle_line = theme.center(line, width)
        print(f"{theme.DIM}{subtitle_line}{theme.RESET}")
    
    # Add decorative separator with skull motifs
    skull_separator = "☠═══════════════════════════════════════════════════════════════════════════☠"
    separator_line = theme.center(skull_separator, width)
    print(f"\n{theme.ACCENT_MAGENTA}{separator_line}{theme.RESET}")
    
    # Add warning message
    warning = "[ HIGH-GRADE ENCRYPTION • LSB STEGANOGRAPHY • AUTHENTICATED EMBEDDING ]"
    warning_line = theme.center(warning, width)
    print(f"{theme.WARNING}{warning_line}{theme.RESET}")
    
    # Close separator
    separator_line = theme.center(skull_separator, width)
    print(f"{theme.ACCENT_MAGENTA}{separator_line}{theme.RESET}")


def print_carriers_panel():
    """Print the payload carriers information panel"""
    from secure_stego import get_supported_image_extensions
    
    supported_formats = ", ".join(get_supported_image_extensions())
    
    lines = [
        f"{theme.ACCENT_CYAN}▶{theme.RESET} SUPPORTED FORMATS: {theme.DIM}{supported_formats}{theme.RESET}",
        f"{theme.ACCENT_CYAN}▶{theme.RESET} OPTIMAL CARRIER: {theme.SUCCESS}PNG (Lossless Compression){theme.RESET}",
        f"{theme.ACCENT_CYAN}▶{theme.RESET} STEGANOGRAPHY: {theme.INFO}LSB Manipulation{theme.RESET}",
    ]
    
    frame_content = theme.frame("PAYLOAD CARRIERS", lines)
    print(f"\n{frame_content}")


def print_menu():
    """Print the main operation menu with proper alignment"""
    print(f"\n{theme.PRIMARY}┌─[ OPERATIONAL MODULES ]{theme.RESET}")
    print(f"{theme.PRIMARY}│{theme.RESET}")
    
    options = [
        ("1", "PAYLOAD_INJECT", "Embed encrypted data into carrier"),
        ("2", "PAYLOAD_EXTRACT", "Decrypt and retrieve hidden data"),
        ("3", "CARRIER_ANALYSIS", "Calculate embedding capacity"),
        ("4", "SYSTEM_HELP", "Display command protocols"),
        ("5", "TERMINATE", "Exit steganography suite"),
    ]
    
    for num, title, desc in options:
        menu_line = theme.menu_option(num, title, desc)
        print(menu_line)
    
    print(f"{theme.PRIMARY}└─────────────────────────────────────────────────────────────{theme.RESET}")


def print_warning_box():
    """Print security warning box"""
    lines = [
        f"{theme.WARNING}WARNING: UNAUTHORIZED ACCESS TO THIS SYSTEM IS PROHIBITED{theme.RESET}",
        f"{theme.WARNING}ALL OPERATIONS ARE LOGGED AND MONITORED{theme.RESET}",
    ]
    
    warning_frame = theme.frame("SECURITY NOTICE", lines)
    print(f"\n{warning_frame}")


def get_operation_choice() -> str:
    """Get user's operation choice with styled prompt"""
    prompt_text = theme.prompt("Enter operation code [1-5]: ")
    return input(f"\n{prompt_text}").strip()


def print_phase_header(phase: str, description: str):
    """Print operation phase header"""
    header = f"PHASE {phase}: {description}"
    print(f"\n{theme.PRIMARY}┌─[ {header} ]{theme.RESET}")
    print(f"{theme.PRIMARY}├─► STATUS: {theme.SUCCESS}INITIALIZING{theme.RESET}")
    print(f"{theme.PRIMARY}└─► {theme.DIM}Please stand by...{theme.RESET}")


def print_operation_complete(operation: str):
    """Print operation completion message"""
    print(f"\n{theme.SUCCESS}✓ {operation.upper()} OPERATION COMPLETED SUCCESSFULLY{theme.RESET}")
    print(f"{theme.DIM}  All security protocols maintained.{theme.RESET}")


def print_termination_sequence():
    """Print styled termination sequence"""
    sequence = [
        ">>> TERMINATING STEGANOGRAPHY SUITE...",
        ">>> SECURITY PROTOCOLS DISENGAGED",
        ">>> WIPING TEMPORARY BUFFERS...", 
        ">>> CONNECTION CLOSED",
        ">>> GOODBYE, OPERATIVE."
    ]
    
    for line in sequence:
        print(f"{theme.DIM}    {line}{theme.RESET}")
