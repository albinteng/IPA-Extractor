# -*- coding: utf-8 -*-
"""The list of apps: a table whose rows are named by bundle id, with the small set of operations the window needs
(the window's code was written against Tk's Treeview, and keeps its shape)."""

from PySide6.QtCore import QPoint, QPointF, QRect, Qt, Signal
from PySide6.QtGui import QBrush, QColor, QPainter, QPen
from PySide6.QtWidgets import (QAbstractItemView, QHeaderView, QLabel, QStyledItemDelegate, QTreeWidget,
                               QTreeWidgetItem)

from gui.theme import PALETTE

BUNDLE = Qt.UserRole
CHECK = Qt.UserRole + 1         # True / False: the row's check box; None: no box (nothing to extract)
BOX = 16


def draw_box(painter, area, checked):
    """A check box in the style of the window's other check boxes, centred in `area`."""
    box = QRect(area.x() + (area.width() - BOX) // 2, area.y() + (area.height() - BOX) // 2, BOX, BOX)
    painter.save()
    painter.setRenderHint(QPainter.Antialiasing)
    color = QColor(PALETTE['accent'] if checked else PALETTE['muted'])
    painter.setPen(QPen(color, 1))
    painter.setBrush(color if checked else QColor(PALETTE['field']))
    painter.drawRoundedRect(box.adjusted(0, 0, -1, -1), 4, 4)
    if checked:
        pen = QPen(QColor(PALETTE['accent_text']), 2)
        pen.setCapStyle(Qt.RoundCap)
        pen.setJoinStyle(Qt.RoundJoin)
        painter.setPen(pen)
        painter.drawPolyline([QPointF(box.x() + 3.5, box.y() + 8.5), QPointF(box.x() + 6.5, box.y() + 11.5),
                              QPointF(box.x() + 12.5, box.y() + 4.5)])
    painter.restore()


class CheckDelegate(QStyledItemDelegate):
    """Draws the check box of the first column; the rest of the cell is the usual one."""

    def paint(self, painter, option, index):
        super().paint(painter, option, index)
        if index.column() == 0:
            state = index.data(CHECK)
            if state is not None:
                draw_box(painter, option.rect, bool(state))


class CheckHeader(QHeaderView):
    """The header of the table: the box in its first section checks (or unchecks) every shown app."""

    def __init__(self, parent=None):
        super().__init__(Qt.Horizontal, parent)
        self.all_checked = False
        self.setDefaultAlignment(Qt.AlignLeft | Qt.AlignVCenter)

    def paintSection(self, painter, rect, logical_index):
        super().paintSection(painter, rect, logical_index)
        if logical_index == 0:
            draw_box(painter, rect, self.all_checked)


class AppTree(QTreeWidget):
    selection_changed = Signal()
    check_clicked = Signal(str, bool)          # bundle, Shift held
    row_double_clicked = Signal(str)
    space_pressed = Signal()
    menu_requested = Signal(str, QPoint)       # bundle, where (screen coordinates)
    header_clicked = Signal(int)

    def __init__(self, columns, parent=None):
        super().__init__(parent)
        self.keys = [key for key, _ in columns]
        self.setHeader(CheckHeader(self))
        self.setItemDelegateForColumn(0, CheckDelegate(self))
        self.setColumnCount(len(columns))
        self.setRootIsDecorated(False)
        self.setUniformRowHeights(True)
        self.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.setSortingEnabled(False)            # the window sorts (natural order), the header only reports clicks
        self.setAllColumnsShowFocus(True)
        header = self.header()
        header.setSectionsClickable(True)
        header.setStretchLastSection(False)
        header.setSectionResizeMode(QHeaderView.Interactive)
        header.setMinimumSectionSize(40)
        header.setSortIndicatorShown(True)
        header.sectionClicked.connect(self.header_clicked.emit)
        for index, (key, width) in enumerate(columns):
            self.setColumnWidth(index, width)
        self.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.itemSelectionChanged.connect(self.selection_changed.emit)
        self._items = {}
        self.busy_label = QLabel(self.viewport())
        self.busy_label.setObjectName('treebusy')
        self.busy_label.hide()

    # ------------------------------------------------------------------ the Treeview-like operations
    def get_children(self):
        """The bundle ids in the order shown."""
        return [self.topLevelItem(i).data(0, BUNDLE) for i in range(self.topLevelItemCount())]

    def exists(self, bundle):
        return bundle in self._items

    def selection(self):
        return [item.data(0, BUNDLE) for item in self.selectedItems()]

    def selection_set(self, bundles):
        self.blockSignals(True)
        self.clearSelection()
        for bundle in bundles:
            if bundle in self._items:
                self._items[bundle].setSelected(True)
        self.blockSignals(False)
        self.selection_changed.emit()

    def delete_all(self):
        self.blockSignals(True)
        self.clear()
        self.blockSignals(False)
        self._items = {}

    def insert(self, bundle, values, tags=(), check=None):
        item = QTreeWidgetItem(self)
        item.setData(0, BUNDLE, bundle)
        self._items[bundle] = item
        self.item(bundle, values, tags, check)

    def item(self, bundle, values, tags=(), check=None):
        item = self._items[bundle]
        for column, value in enumerate(values):
            item.setText(column, value)
        item.setData(0, CHECK, check)
        self._paint(item, tags)

    def row_check(self, bundle):
        """The state of a row's check box: True, False, or None when it has none."""
        return self._items[bundle].data(0, CHECK)

    def set_all_checked(self, value):
        """The state of the header's box: whether every shown app is checked."""
        header = self.header()
        if header.all_checked != value:
            header.all_checked = value
            header.viewport().update()

    def _paint(self, item, tags):
        foreground = None
        for tag in ('done', 'failed', 'partial', 'running', 'queued', 'offloaded'):
            if tag in tags:
                foreground = QBrush(QColor(PALETTE['idle' if tag == 'offloaded' else {'done': 'ok'}.get(tag, tag)]))
        background = QBrush(QColor(PALETTE['checked'])) if 'checked' in tags else QBrush()
        for column in range(self.columnCount()):
            item.setBackground(column, background)
            item.setForeground(column, foreground or QBrush())

    def see(self, bundle):
        if bundle in self._items:
            self.scrollToItem(self._items[bundle])

    def set_sort_indicator(self, key, descending):
        self.header().setSortIndicator(self.keys.index(key),
                                       Qt.DescendingOrder if descending else Qt.AscendingOrder)

    def set_busy(self, text, visible):
        self.busy_label.setText(text)
        self.busy_label.adjustSize()
        self._center_busy_label()
        self.busy_label.setVisible(visible)

    def _center_busy_label(self):
        area = self.viewport().rect()
        self.busy_label.move((area.width() - self.busy_label.width()) // 2,
                             int(area.height() * 0.4) - self.busy_label.height() // 2)

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self._center_busy_label()

    # ------------------------------------------------------------------ the mouse and the keyboard
    def _bundle_at(self, pos):
        item = self.itemAt(pos)
        return item.data(0, BUNDLE) if item is not None else None

    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton and not (event.modifiers() & Qt.ControlModifier and sys_is_macos()):
            bundle = self._bundle_at(event.position().toPoint())
            if bundle and self.columnAt(event.position().toPoint().x()) == 0:
                self.check_clicked.emit(bundle, bool(event.modifiers() & Qt.ShiftModifier))
                return                      # the click is the checkbox's: the selection stays as it is
        if event.button() == Qt.RightButton:
            return                          # the context menu handles it (and keeps the selection of the row)
        super().mousePressEvent(event)

    def mouseDoubleClickEvent(self, event):
        # A fast second click on a checkbox arrives here, so every double-click on a row toggles it exactly once.
        if event.button() == Qt.LeftButton:
            bundle = self._bundle_at(event.position().toPoint())
            if bundle:
                self.row_double_clicked.emit(bundle)
            return
        super().mouseDoubleClickEvent(event)

    def keyPressEvent(self, event):
        if event.key() == Qt.Key_Space:
            self.space_pressed.emit()
            return
        super().keyPressEvent(event)

    def contextMenuEvent(self, event):
        self.menu_requested.emit(self._bundle_at(event.pos()) or '', event.globalPos())


def sys_is_macos():
    import sys
    return sys.platform == 'darwin'
