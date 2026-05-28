"""Base page class with common layout."""
from PyQt5.QtWidgets import QWidget, QVBoxLayout
from ui.widgets.header_bar import HeaderBar


class BasePage(QWidget):
    PAGE_TITLE = "Page"

    def __init__(self, main_window, show_dashboard: bool = True,
                 show_results: bool = False):
        super().__init__()
        self.main_window = main_window
        self._root = QVBoxLayout(self)
        self._root.setContentsMargins(0, 0, 0, 0)
        self._root.setSpacing(0)

        self._header = HeaderBar(self.PAGE_TITLE,
                                  show_dashboard=show_dashboard,
                                  show_results=show_results)
        self._header.dashboard_clicked.connect(
            lambda: main_window.navigate_to("dashboard"))
        self._header.settings_clicked.connect(
            lambda: main_window.navigate_to("settings"))
        self._header.results_clicked.connect(
            lambda: main_window.navigate_to("results"))
        self._root.addWidget(self._header)

        self.body = QWidget()
        self.body.setStyleSheet("background: transparent;")
        self._root.addWidget(self.body, 1)

    def showEvent(self, event):
        super().showEvent(event)
        self._on_show()

    def _on_show(self):
        """Override to refresh data when page becomes visible."""
        pass