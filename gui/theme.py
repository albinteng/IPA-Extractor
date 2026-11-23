# -*- coding: utf-8 -*-
"""Colours, the style sheet and the fonts of the window; light, dark and pure black themes."""

import sys

from PySide6.QtGui import QColor, QFont, QFontDatabase
from PySide6.QtWidgets import QApplication

from engine import IS_WINDOWS, THEME_BLACK, THEME_DARK, THEME_LIGHT, resolve_theme

_STATUS_LIGHT = dict(ok='#1a7f37', busy='#d4a72c', error='#cf222e', idle='#8c959f',
                     partial='#bc4c00', running='#0969da', queued='#9a6700')
_STATUS_DARK = dict(ok='#3fb950', busy='#d29922', error='#f85149', idle='#6e7681',
                    partial='#f0883e', running='#58a6ff', queued='#d29922')
PALETTES = {
    THEME_LIGHT: dict(bg='#f3f3f3', card='#ffffff', side='#ececec', field='#ffffff', button='#fbfbfb', hover='#ececec',
                      border='#dadada', fg='#1b1b1b', muted='#616161', select='#dfeaf6', checked='#e3f0fc',
                      accent='#0067c0', accent_text='#ffffff', tooltip='#ffffe0', off='#c9c9c9', **_STATUS_LIGHT),
    THEME_DARK: dict(bg='#202020', card='#2b2b2b', side='#1b1b1b', field='#323232', button='#323232', hover='#3a3a3a',
                     border='#3d3d3d', fg='#f0f0f0', muted='#a0a0a0', select='#1f3a52', checked='#1c3a57',
                     accent='#4cc2ff', accent_text='#00263d', tooltip='#2d2d2d', off='#5c5c5c', **_STATUS_DARK),
    THEME_BLACK: dict(bg='#000000', card='#111111', side='#000000', field='#161616', button='#161616', hover='#222222',
                      border='#2a2a2a', fg='#f0f0f0', muted='#8f8f8f', select='#0d2a47', checked='#0d2a47',
                      accent='#4cc2ff', accent_text='#00263d', tooltip='#111111', off='#585858', **_STATUS_DARK),
}
PALETTE = dict(PALETTES[THEME_LIGHT])       # the colours in use; changed in place by apply_theme()


def stylesheet(p, size):
    return """
    * {{ font-size: {size}pt; }}
    QWidget {{ color: {fg}; }}
    QMainWindow, QDialog, QWidget#root, QScrollArea, QScrollArea > QWidget > QWidget {{ background: {bg}; }}
    QScrollArea {{ border: none; }}
    QListWidget#nav {{ background: {side}; border: none; outline: none; padding: 8px; }}
    QListWidget#nav::item {{ padding: 9px 12px; border-radius: 6px; margin: 1px 0; }}
    QListWidget#nav::item:hover {{ background: {hover}; }}
    QListWidget#nav::item:selected {{ background: {select}; color: {fg}; }}
    QFrame#card {{ background: {card}; border: 1px solid {border}; border-radius: 8px; }}
    QFrame#card QLabel {{ background: transparent; }}
    QFrame#bar {{ background: {card}; border: none; border-top: 1px solid {border}; }}
    QLabel {{ background: transparent; }}
    QLabel#muted {{ color: {muted}; }}
    QLabel#title {{ font-size: {title}pt; font-weight: 600; }}
    QLabel#cardtitle {{ font-weight: 600; }}
    QLabel#link {{ color: {accent}; }}
    QLabel#treebusy {{ color: {muted}; background: transparent; }}
    QLineEdit, QComboBox, QSpinBox, QPlainTextEdit, QTextEdit {{ background: {field}; border: 1px solid {border};
        border-radius: 5px; padding: 4px 8px; selection-background-color: {accent}; selection-color: {accent_text}; }}
    QLineEdit, QComboBox, QSpinBox {{ min-height: 20px; }}
    QLineEdit:focus, QComboBox:focus, QSpinBox:focus, QPlainTextEdit:focus {{ border: 1px solid {accent}; }}
    QLineEdit:disabled, QComboBox:disabled, QSpinBox:disabled {{ color: {muted}; background: {bg}; }}
    QComboBox::drop-down {{ border: none; width: 22px; }}
    QComboBox QAbstractItemView {{ background: {card}; border: 1px solid {border}; selection-background-color: {select};
        selection-color: {fg}; outline: none; }}
    QSpinBox::up-button, QSpinBox::down-button {{ width: 18px; border: none; background: transparent; }}
    QPushButton {{ background: {button}; border: 1px solid {border}; border-radius: 5px; padding: 5px 14px; }}
    QPushButton:hover {{ background: {hover}; }}
    QPushButton:pressed {{ background: {select}; }}
    QPushButton:disabled {{ color: {muted}; background: {bg}; }}
    QPushButton#primary {{ background: {accent}; color: {accent_text}; border: 1px solid {accent}; font-weight: 600; }}
    QPushButton#primary:disabled {{ background: {border}; color: {muted}; border: 1px solid {border}; }}
    QPushButton#chip {{ padding: 2px 10px; border-radius: 11px; }}
    QCheckBox, QRadioButton {{ spacing: 8px; background: transparent; }}
    QCheckBox:disabled, QRadioButton:disabled {{ color: {muted}; }}
    QCheckBox::indicator, QRadioButton::indicator {{ width: 16px; height: 16px; }}
    QCheckBox::indicator {{ border: 1px solid {muted}; border-radius: 4px; background: {field}; }}
    QCheckBox::indicator:checked {{ background: {accent}; border: 1px solid {accent}; image: url({check}); }}
    QRadioButton::indicator {{ border: 1px solid {muted}; border-radius: 8px; background: {field}; }}
    QRadioButton::indicator:checked {{ width: 8px; height: 8px; background: {field}; border: 5px solid {accent}; border-radius: 9px; }}
    QCheckBox::indicator:disabled {{ border: 1px solid {off}; background: {card}; }}
    QCheckBox::indicator:checked:disabled {{ background: {off}; border: 1px solid {off}; image: url({check_off}); }}
    QRadioButton::indicator:disabled {{ border: 1px solid {off}; background: {card}; }}
    QRadioButton::indicator:checked:disabled {{ width: 8px; height: 8px; background: {card}; border: 5px solid {off}; border-radius: 9px; }}
    QTreeWidget {{ background: {field}; alternate-background-color: {field}; border: 1px solid {border}; border-radius: 6px;
        outline: none; selection-background-color: {select}; selection-color: {fg}; }}
    QTreeWidget::item {{ padding: 3px 2px; }}
    QHeaderView::section {{ background: {button}; color: {fg}; border: none; border-right: 1px solid {border};
        border-bottom: 1px solid {border}; padding: 5px 6px; font-weight: 600; }}
    QProgressBar {{ background: {field}; border: 1px solid {border}; border-radius: 5px; min-height: 12px; max-height: 12px; }}
    QProgressBar::chunk {{ background: {accent}; border-radius: 4px; }}
    QSplitter::handle {{ background: {bg}; }}
    QScrollBar:vertical {{ background: transparent; width: 12px; margin: 2px; }}
    QScrollBar::handle:vertical {{ background: {border}; border-radius: 4px; min-height: 30px; }}
    QScrollBar::handle:vertical:hover {{ background: {muted}; }}
    QScrollBar:horizontal {{ background: transparent; height: 12px; margin: 2px; }}
    QScrollBar::handle:horizontal {{ background: {border}; border-radius: 4px; min-width: 30px; }}
    QScrollBar::add-line, QScrollBar::sub-line {{ height: 0; width: 0; }}
    QMenu {{ background: {card}; border: 1px solid {border}; padding: 4px; }}
    QMenu::item {{ padding: 6px 22px; border-radius: 4px; }}
    QMenu::item:selected {{ background: {select}; color: {fg}; }}
    QMessageBox {{ background: {bg}; }}
    QToolTip {{ background: {card}; color: {fg}; border: 1px solid {border}; padding: 4px; }}
    """.format(size=size, title=size + 6, **p)


def check_icon(name='check.svg'):
    import os
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), name).replace(os.sep, '/')


def apply_theme(app, setting, size):
    """Make the palette of `setting` (a theme setting, which may be "system") the one in use and style the application."""
    name = resolve_theme(setting)
    PALETTE.clear()
    PALETTE.update(PALETTES[name])
    app.setStyle('Fusion')           # the same drawing on every system; the style sheet does the rest
    app.setStyleSheet(stylesheet(dict(PALETTE, check=check_icon(), check_off=check_icon('check_disabled.svg')), size))
    return name


def style_titlebar(widget, setting):
    """Dark title bar on Windows 10 and 11 for the dark themes; other systems keep theirs."""
    if not IS_WINDOWS:
        return
    try:
        import ctypes
        handle = int(widget.winId())
        value = ctypes.c_int(0 if resolve_theme(setting) == THEME_LIGHT else 1)
        for attribute in (20, 19):   # DWMWA_USE_IMMERSIVE_DARK_MODE, and its number before Windows 10 20H1
            ctypes.windll.dwmapi.DwmSetWindowAttribute(handle, attribute, ctypes.byref(value), ctypes.sizeof(value))
    except (OSError, AttributeError):
        pass


def installed_fonts():
    return sorted(f for f in QFontDatabase.families() if not f.startswith('@'))


def apply_font(app, family, size):
    font = QFont(family)
    font.setPointSize(size)
    app.setFont(font)


def color(name):
    return QColor(PALETTE[name])
