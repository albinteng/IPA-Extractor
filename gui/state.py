# -*- coding: utf-8 -*-
"""Settings values with change callbacks, and the glue that ties them to Qt widgets.

The window's logic keeps one Var per setting (host, port, theme, ...), read with get() and written with set(), as it
did with Tk's StringVar and BooleanVar; widgets are bound to the Vars, so a value changed in the code shows in the widget
and the other way round.
"""


class Var:
    """A value that tells its callbacks when it is set (also when it is set to what it already is)."""

    def __init__(self, value=''):
        self._value = value
        self._callbacks = []

    def _coerce(self, value):
        return value

    def get(self):
        return self._value

    def set(self, value):
        self._value = self._coerce(value)
        for callback in list(self._callbacks):
            try:
                callback()
            except RuntimeError as error:
                if 'already deleted' not in str(error):
                    raise
                self.trace_remove('write', callback)      # the widget it served is gone

    def trace_add(self, mode, callback):
        self._callbacks.append(callback)
        return callback

    def trace_info(self):
        return [('write', callback) for callback in self._callbacks]

    def trace_remove(self, mode, callback):
        if callback in self._callbacks:
            self._callbacks.remove(callback)


class StringVar(Var):
    def __init__(self, value=''):
        super().__init__(str(value))

    def _coerce(self, value):
        return str(value)


class BooleanVar(Var):
    def __init__(self, value=False):
        super().__init__(bool(value))

    def _coerce(self, value):
        return bool(value)


# ------------------------------------------------------------------ binding to widgets
def _bound(widget, var, callback):
    """Watch var with callback for as long as the widget lives: a window that is rebuilt or closed leaves nothing behind
    that would call into its deleted widgets."""
    var.trace_add('write', callback)
    widget.destroyed.connect(lambda *args, v=var, c=callback: v.trace_remove('write', c))
    return callback


def bind_text(edit, var):
    """A QLineEdit shows var and writes what is typed into it."""
    edit.setText(var.get())

    def from_widget(text):
        if var.get() != text:
            var.set(text)

    def from_var():
        if edit.text() != var.get():
            edit.blockSignals(True)
            edit.setText(var.get())
            edit.blockSignals(False)
    edit.textChanged.connect(from_widget)
    return _bound(edit, var, from_var)


def bind_check(box, var):
    """A QCheckBox (or any checkable button) shows var and sets it."""
    box.setChecked(bool(var.get()))
    box.toggled.connect(lambda checked: var.set(checked) if var.get() != checked else None)

    def from_var():
        if box.isChecked() != bool(var.get()):
            box.blockSignals(True)
            box.setChecked(bool(var.get()))
            box.blockSignals(False)
    return _bound(box, var, from_var)


def bind_radio(button, var, value, command=None):
    """A radio button that is on while var holds `value`; choosing it sets var (and then runs command)."""
    button.setChecked(var.get() == value)

    def toggled(checked):
        if checked:
            var.set(value)
            if command is not None:
                command()
    button.toggled.connect(toggled)

    def from_var():
        want = var.get() == value
        if button.isChecked() != want:
            button.blockSignals(True)
            button.setChecked(want)
            button.blockSignals(False)
    return _bound(button, var, from_var)
