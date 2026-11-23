# -*- coding: utf-8 -*-
"""Starting the window: the application object, the packages the program needs, the main window."""

import subprocess
import sys

from PySide6.QtCore import Qt
from PySide6.QtGui import QCursor
from PySide6.QtWidgets import QApplication, QMessageBox

import engine
import i18n
from engine import BASE_PACKAGES, IS_WINDOWS, NO_WINDOW, load_config, pip_install


def install_base_packages(app):
    """Ask to pip install what the tool needs to start; True once paramiko imports."""
    locales = i18n.load_locales()
    strings = locales[i18n.resolve(locales, load_config().get('lang', i18n.AUTO))]

    def t(key, **params):
        return (strings.get(key) or locales[i18n.FALLBACK][key]).format(**params)

    command = pip_install(BASE_PACKAGES)
    answer = QMessageBox.question(None, t('m_missing_t'), t('m_missing', packages='\n'.join(BASE_PACKAGES),
                                                            command=' '.join(command)))
    if answer != QMessageBox.Yes:
        return False
    app.setOverrideCursor(QCursor(Qt.WaitCursor))       # a wait cursor while pip runs
    try:
        process = subprocess.run(command, stdin=subprocess.DEVNULL, capture_output=True, text=True, encoding='utf-8',
                                 errors='replace', creationflags=NO_WINDOW)
        if process.returncode:
            raise RuntimeError((process.stdout + process.stderr).strip()[-1500:])
        import importlib
        importlib.invalidate_caches()
        engine.paramiko = importlib.import_module('paramiko')
    except Exception as error:
        app.restoreOverrideCursor()
        QMessageBox.critical(None, t('m_missing_t'), t('m_missing_failed', error=error))
        return False
    app.restoreOverrideCursor()
    return True


def main():
    if IS_WINDOWS:
        # Without its own app ID, pythonw's taskbar button shows the Python icon.
        try:
            import ctypes
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID('IPAExtractor')
        except (AttributeError, OSError):
            pass
    app = QApplication.instance() or QApplication(sys.argv[:1])
    app.setApplicationName(engine.APP_NAME)
    if engine.paramiko is None and not engine.app_paths.FROZEN and not install_base_packages(app):
        return 1
    from gui.main_window import MainWindow
    window = MainWindow(app)
    window.show()
    window.style_titlebar(window)
    return app.exec()
