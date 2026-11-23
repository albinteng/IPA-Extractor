# -*- coding: utf-8 -*-
"""Message boxes and the folder picker, in one place: the window's code calls these, and the tests replace them.

The buttons carry the texts of the chosen UI language (translate is set by the window); Qt's own would follow the
system language instead.
"""

from PySide6.QtWidgets import QApplication, QFileDialog, QMessageBox

translate = None          # t(key) of the window, set once it exists
parent_widget = None      # the window: the default parent of every box


def _text(key, fallback):
    try:
        return translate(key) if translate is not None else fallback
    except Exception:
        return fallback


def _show(icon, title, message, buttons, parent):
    box = QMessageBox(parent or parent_widget)
    box.setIcon(icon)
    box.setWindowTitle(title)
    box.setText(message)
    box.setTextInteractionFlags(box.textInteractionFlags())
    result = {}
    if buttons == 'yesno':
        yes = box.addButton(_text('yes', 'Yes'), QMessageBox.YesRole)
        box.addButton(_text('no', 'No'), QMessageBox.NoRole)
        box.setDefaultButton(yes)
        result['yes'] = yes
    else:
        ok = box.addButton('OK', QMessageBox.AcceptRole)
        box.setDefaultButton(ok)
    box.exec()
    return box.clickedButton() is result.get('yes')


def showinfo(title, message, parent=None):
    _show(QMessageBox.Information, title, message, 'ok', parent)


def showwarning(title, message, parent=None):
    _show(QMessageBox.Warning, title, message, 'ok', parent)


def showerror(title, message, parent=None):
    _show(QMessageBox.Critical, title, message, 'ok', parent)


def askyesno(title, message, parent=None):
    return _show(QMessageBox.Question, title, message, 'yesno', parent)


def askdirectory(title='', initialdir='', parent=None):
    """The folder the user picked, or '' when the dialog was cancelled."""
    return QFileDialog.getExistingDirectory(parent or parent_widget, title or '', initialdir or '')
