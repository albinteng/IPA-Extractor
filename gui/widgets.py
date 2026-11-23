# -*- coding: utf-8 -*-
"""Small widgets shared by the windows."""

from PySide6.QtCore import QEvent, QPoint, QRect, QSize, Qt, QTimer
from PySide6.QtGui import QColor, QPainter
from PySide6.QtWidgets import (QFrame, QHBoxLayout, QLabel, QLayout, QRadioButton, QVBoxLayout, QWidget)

from gui.theme import PALETTE


class StatusDot(QWidget):
    """A round dot in one of the status colours."""

    def __init__(self, color='idle', parent=None):
        super().__init__(parent)
        self.color = color
        self.setFixedSize(14, 14)

    def set_color(self, name):
        self.color = name
        self.update()

    def sizeHint(self):
        return QSize(14, 14)

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        painter.setPen(Qt.NoPen)
        painter.setBrush(QColor(PALETTE.get(self.color, PALETTE['idle'])))
        painter.drawEllipse(2, 2, 10, 10)


class DotLabel(QWidget):
    """A status dot with a text beside it. The dot sits on the middle of the text's first line: of the capital letters
    for Latin and other alphabets (the middle of the line box would put it too high), of the line for Chinese,
    Japanese and Korean."""

    def __init__(self, wrap, parent=None):
        super().__init__(parent)
        row = QHBoxLayout(self)
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(8)
        self.dot = StatusDot()
        self.holder = QWidget()
        column = QVBoxLayout(self.holder)
        column.setContentsMargins(0, 0, 0, 0)
        column.addWidget(self.dot)
        self.label = QLabel()
        self.label.setWordWrap(wrap)
        row.addWidget(self.holder, 0, Qt.AlignTop)
        row.addWidget(self.label, 1, Qt.AlignTop)
        self.align()

    def align(self):
        try:
            metrics = self.label.fontMetrics()
        except RuntimeError:             # called by the timer after the window was closed
            return
        text = self.label.text()
        if any(ord(ch) >= 0x2E80 for ch in text):
            centre = (metrics.ascent() + metrics.descent()) / 2
        else:
            centre = metrics.ascent() - metrics.capHeight() / 2
        self.holder.setContentsMargins(0, max(0, round(centre - self.dot.height() / 2)), 0, 0)

    def show_text(self, text, color):
        self.label.setText(text)
        self.dot.set_color(color)
        self.align()
        QTimer.singleShot(0, self.align)         # once the style sheet has given the label its font

    def changeEvent(self, event):
        super().changeEvent(event)
        if event.type() in (QEvent.FontChange, QEvent.StyleChange):
            self.align()


class Indicator(DotLabel):
    """"SSH: connected": a status dot and its text."""

    def __init__(self, title, parent=None):
        super().__init__(False, parent)
        self.title = title
        self.layout().setContentsMargins(6, 0, 18, 0)

    def set(self, text, color):
        self.show_text('{}: {}'.format(self.title, text), color)


class StatusLine(DotLabel):
    """A status dot with its text: the state of something at a glance, without symbols in the text."""

    def __init__(self, parent=None):
        super().__init__(True, parent)

    def set(self, text, color):
        self.show_text(text, color)


class Card(QFrame):
    """A rounded panel; add widgets and layouts to .box."""

    def __init__(self, title=None, parent=None):
        super().__init__(parent)
        self.setObjectName('card')
        self.box = QVBoxLayout(self)
        self.box.setContentsMargins(16, 14, 16, 16)
        self.box.setSpacing(10)
        if title:
            heading = QLabel(title)
            heading.setObjectName('cardtitle')
            self.box.addWidget(heading)


def muted_label(text='', wrap=True):
    label = QLabel(text)
    label.setObjectName('muted')
    label.setWordWrap(wrap)
    return label


class Option(QFrame):
    """A radio button with its explanation under it (what the old window hid in a tooltip)."""

    def __init__(self, text, tip='', parent=None):
        super().__init__(parent)
        box = QVBoxLayout(self)
        box.setContentsMargins(0, 0, 0, 0)
        box.setSpacing(2)
        self.radio = QRadioButton(text)
        box.addWidget(self.radio)
        self.hint = None
        if tip:
            self.hint = muted_label(tip)
            self.hint.setContentsMargins(24, 0, 0, 0)
            box.addWidget(self.hint)

    def setEnabled(self, enabled):
        super().setEnabled(enabled)


class FlowLayout(QLayout):
    """Lays its items out left to right and starts a new line when the next one does not fit: a row of controls that
    cannot overflow the window, however big the font or long the translation."""

    def __init__(self, parent=None, hspacing=8, vspacing=6):
        super().__init__(parent)
        self.items = []
        self.hspacing, self.vspacing = hspacing, vspacing
        self.setContentsMargins(0, 0, 0, 0)

    def addItem(self, item):
        self.items.append(item)

    def count(self):
        return len(self.items)

    def itemAt(self, index):
        return self.items[index] if 0 <= index < len(self.items) else None

    def takeAt(self, index):
        return self.items.pop(index) if 0 <= index < len(self.items) else None

    def expandingDirections(self):
        return Qt.Orientation(0)

    def hasHeightForWidth(self):
        return True

    def heightForWidth(self, width):
        return self._arrange(QRect(0, 0, width, 0), apply=False)

    def setGeometry(self, rect):
        super().setGeometry(rect)
        self._arrange(rect, apply=True)

    def sizeHint(self):
        return self.minimumSize()

    def minimumSize(self):
        size = QSize()
        for item in self.items:
            size = size.expandedTo(item.minimumSize())
        margins = self.contentsMargins()
        return size + QSize(margins.left() + margins.right(), margins.top() + margins.bottom())

    def _arrange(self, rect, apply):
        margins = self.contentsMargins()
        area = rect.adjusted(margins.left(), margins.top(), -margins.right(), -margins.bottom())
        # First the lines (which items fit side by side), then each item on the middle of its line: a check box beside a
        # button or an entry would otherwise sit at the top.
        lines, current, x = [], [], area.x()
        for item in self.items:
            hint = item.sizeHint()
            if current and x + hint.width() > area.right() + 1:
                lines.append(current)
                current, x = [], area.x()
            current.append((item, hint))
            x += hint.width() + self.hspacing
        if current:
            lines.append(current)
        y = area.y()
        for line in lines:
            height = max(hint.height() for _, hint in line)
            x = area.x()
            for item, hint in line:
                if apply:
                    item.setGeometry(QRect(QPoint(x, y + (height - hint.height()) // 2), hint))
                x += hint.width() + self.hspacing
            y += height + self.vspacing
        return (y - self.vspacing if lines else y) - rect.y() + margins.bottom()


def pair(label, widget):
    """A label with its field, as one item of a FlowLayout (they wrap together)."""
    holder = QWidget()
    row = QHBoxLayout(holder)
    row.setContentsMargins(0, 0, 0, 0)
    row.setSpacing(6)
    row.addWidget(QLabel(label) if isinstance(label, str) else label)
    row.addWidget(widget)
    return holder
