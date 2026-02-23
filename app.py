import sys
from datetime import datetime
from typing import Dict, List, Any

from PyQt5.QtCore import Qt, QAbstractTableModel, QModelIndex
from PyQt5.QtWidgets import (
    QApplication,
    QDialog,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QPlainTextEdit,
    QSplitter,
    QTableView,
    QTableWidget,
    QTableWidgetItem,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)


class VulnerabilityTableModel(QAbstractTableModel):
    HEADERS = ["코드", "취약점명", "상태", "결과"]

    def __init__(self, rows: List[List[str]], parent=None):
        super().__init__(parent)
        self._rows = rows

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:
        if parent.isValid():
            return 0
        return len(self._rows)

    def columnCount(self, parent: QModelIndex = QModelIndex()) -> int:
        if parent.isValid():
            return 0
        return len(self.HEADERS)

    def data(self, index: QModelIndex, role: int = Qt.DisplayRole):
        if not index.isValid() or role != Qt.DisplayRole:
            return None
        return self._rows[index.row()][index.column()]

    def headerData(self, section: int, orientation: Qt.Orientation, role: int = Qt.DisplayRole):
        if role != Qt.DisplayRole:
            return None
        if orientation == Qt.Horizontal:
            return self.HEADERS[section]
        return str(section + 1)


class ReportDialog(QDialog):
    def __init__(self, payload: Dict[str, Any], parent=None):
        super().__init__(parent)
        self.payload = payload
        self.setWindowTitle(payload.get("title", "리포트"))
        self.resize(620, 520)

        layout = QVBoxLayout(self)

        graph_placeholder = QLabel("그래프 영역 (placeholder)")
        graph_placeholder.setAlignment(Qt.AlignCenter)
        graph_placeholder.setStyleSheet("border: 1px solid #999; padding: 28px; background: #f8f8f8;")
        layout.addWidget(graph_placeholder)

        self.summary_view = QPlainTextEdit()
        self.summary_view.setReadOnly(True)
        self.summary_view.setPlainText(payload.get("text", ""))
        layout.addWidget(self.summary_view)

        self.table_widget = QTableWidget(0, 3)
        self.table_widget.setHorizontalHeaderLabels(["항목", "값", "비고"])
        self.table_widget.verticalHeader().setVisible(False)
        self._populate_table(payload.get("table", []))
        layout.addWidget(self.table_widget)

        button_layout = QHBoxLayout()
        button_layout.addStretch(1)
        save_btn = QPushButton("저장")
        close_btn = QPushButton("닫기")
        save_btn.clicked.connect(self._save_as_txt)
        close_btn.clicked.connect(self.close)
        button_layout.addWidget(save_btn)
        button_layout.addWidget(close_btn)
        layout.addLayout(button_layout)

    def _populate_table(self, rows: List[List[str]]):
        self.table_widget.setRowCount(len(rows))
        for r_idx, row in enumerate(rows):
            for c_idx, value in enumerate(row[:3]):
                self.table_widget.setItem(r_idx, c_idx, QTableWidgetItem(str(value)))
        self.table_widget.resizeColumnsToContents()

    def _save_as_txt(self):
        default_name = self.payload.get("title", "report").replace(" ", "_") + ".txt"
        path, _ = QFileDialog.getSaveFileName(self, "리포트 저장", default_name, "Text Files (*.txt)")
        if not path:
            return

        table_lines = []
        for row in self.payload.get("table", []):
            padded = list(row) + [""] * max(0, 3 - len(row))
            table_lines.append(f"- {padded[0]} | {padded[1]} | {padded[2]}")

        body = [
            f"제목: {self.payload.get('title', '')}",
            f"종류: {self.payload.get('kind', '')}",
            f"생성시각: {self.payload.get('created_at_full', '')}",
            "",
            "[요약]",
            self.payload.get("text", ""),
            "",
            "[표 데이터]",
            *table_lines,
        ]

        try:
            with open(path, "w", encoding="utf-8") as fp:
                fp.write("\n".join(body))
            QMessageBox.information(self, "저장 완료", f"리포트를 저장했습니다.\n{path}")
        except OSError as exc:
            QMessageBox.critical(self, "저장 실패", str(exc))


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("서버 취약점 점검 GUI 툴")
        self.resize(900, 520)

        self.date_roots: Dict[str, QTreeWidgetItem] = {}
        self.diag_seq_by_date: Dict[str, int] = {}

        top_widget = QWidget()
        top_layout = QVBoxLayout(top_widget)

        top_buttons = QHBoxLayout()
        self.start_diag_btn = QPushButton("점검 시작")
        self.run_action_btn = QPushButton("조치 실행(더미)")
        top_buttons.addWidget(self.start_diag_btn)
        top_buttons.addWidget(self.run_action_btn)
        top_buttons.addStretch(1)
        top_layout.addLayout(top_buttons)

        splitter = QSplitter(Qt.Horizontal)
        top_layout.addWidget(splitter, 1)
        self.setCentralWidget(top_widget)

        left_panel = QWidget()
        left_layout = QVBoxLayout(left_panel)
        left_layout.addWidget(QLabel("취약점 항목 리스트"))
        self.vuln_table = QTableView()
        left_layout.addWidget(self.vuln_table)
        splitter.addWidget(left_panel)

        right_panel = QWidget()
        right_layout = QVBoxLayout(right_panel)

        self.report_btn = QPushButton("리포트 보기")
        right_layout.addWidget(self.report_btn)

        self.record_tree = QTreeWidget()
        self.record_tree.setHeaderLabel("점검 실행 기록")
        right_layout.addWidget(self.record_tree, 2)

        self.log_view = QPlainTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setPlaceholderText("항목을 선택하면 로그/결과가 표시됩니다.")
        right_layout.addWidget(self.log_view, 1)

        splitter.addWidget(right_panel)
        splitter.setStretchFactor(0, 1)
        splitter.setStretchFactor(1, 2)

        self._setup_models()
        self._connect_signals()

    def _setup_models(self):
        dummy_rows = [
            ["V-001", "불필요한 서비스 비활성화", "대기", "-"],
            ["V-002", "최신 보안 패치 적용", "대기", "-"],
            ["V-003", "로그 정책 설정", "대기", "-"],
        ]
        self.vuln_model = VulnerabilityTableModel(dummy_rows, self)
        self.vuln_table.setModel(self.vuln_model)
        self.vuln_table.horizontalHeader().setStretchLastSection(True)
        self.vuln_table.setSelectionBehavior(QTableView.SelectRows)

    def _connect_signals(self):
        self.start_diag_btn.clicked.connect(self.create_diagnosis_record)
        self.run_action_btn.clicked.connect(self.create_action_record)
        self.record_tree.itemClicked.connect(self.on_tree_item_clicked)
        self.report_btn.clicked.connect(self.open_report_dialog)

    def _now(self):
        now = datetime.now()
        return now.strftime("%Y-%m-%d"), now.strftime("%H:%M:%S"), now.strftime("%Y-%m-%d %H:%M:%S")

    def _ensure_date_root(self, date_str: str) -> QTreeWidgetItem:
        if date_str not in self.date_roots:
            date_item = QTreeWidgetItem([date_str])
            self.record_tree.addTopLevelItem(date_item)
            self.date_roots[date_str] = date_item
            self.diag_seq_by_date.setdefault(date_str, 0)
        return self.date_roots[date_str]

    def create_diagnosis_record(self):
        date_str, time_str, full_str = self._now()
        date_item = self._ensure_date_root(date_str)

        seq = self.diag_seq_by_date.get(date_str, 0) + 1
        self.diag_seq_by_date[date_str] = seq

        diag_name = f"진단{seq}"
        payload = {
            "kind": "diagnosis",
            "created_at_full": full_str,
            "created_time": time_str,
            "title": f"{date_str} {diag_name} 리포트",
            "text": f"{diag_name} 더미 점검 결과입니다.\n추후 실제 점검 로그/판정 결과가 표시됩니다.",
            "table": [
                ["대상", "서버-A", "더미"],
                ["상태", "점검완료", "placeholder"],
                ["요약", "취약점 점검 3건", "예시"],
            ],
            "action_seq": 0,
        }

        diag_item = QTreeWidgetItem([diag_name])
        diag_item.setData(0, Qt.UserRole, payload)
        date_item.addChild(diag_item)
        date_item.setExpanded(True)

        self.record_tree.setCurrentItem(diag_item)
        self.on_tree_item_clicked(diag_item)

    def _resolve_selected_diagnosis(self):
        selected = self.record_tree.currentItem()
        if not selected:
            return None

        payload = selected.data(0, Qt.UserRole)
        if isinstance(payload, dict):
            if payload.get("kind") == "diagnosis":
                return selected
            if payload.get("kind") == "action":
                parent = selected.parent()
                if parent:
                    return parent
        return None

    def create_action_record(self):
        diag_item = self._resolve_selected_diagnosis()
        if diag_item is None:
            QMessageBox.warning(self, "선택 필요", "트리에서 진단 또는 해당 진단 하위 조치를 먼저 선택하세요.")
            return

        diag_payload = diag_item.data(0, Qt.UserRole)
        if not isinstance(diag_payload, dict):
            QMessageBox.warning(self, "오류", "진단 payload를 찾지 못했습니다.")
            return

        next_seq = int(diag_payload.get("action_seq", 0)) + 1
        diag_payload["action_seq"] = next_seq
        diag_item.setData(0, Qt.UserRole, diag_payload)

        date_str, time_str, full_str = self._now()
        action_name = f"조치{next_seq}"
        action_payload = {
            "kind": "action",
            "created_at_full": full_str,
            "created_time": time_str,
            "title": f"{date_str} {diag_item.text(0)} - {action_name} 리포트",
            "text": f"{diag_item.text(0)}에 대한 {action_name} 더미 실행 결과입니다.",
            "table": [
                ["조치대상", diag_item.text(0), "더미"],
                ["조치결과", "성공", "placeholder"],
                ["비고", action_name, "예시"],
            ],
        }

        action_item = QTreeWidgetItem([action_name])
        action_item.setData(0, Qt.UserRole, action_payload)
        diag_item.addChild(action_item)
        diag_item.setExpanded(True)

        self.record_tree.setCurrentItem(action_item)
        self.on_tree_item_clicked(action_item)

    def on_tree_item_clicked(self, item: QTreeWidgetItem):
        payload = item.data(0, Qt.UserRole)
        if not isinstance(payload, dict):
            self.log_view.setPlainText("날짜 노드입니다. 하위 진단/조치 항목을 선택하세요.")
            return

        created_time = payload.get("created_time", "")
        text = payload.get("text", "")
        self.log_view.setPlainText(f"[{created_time}]\n{text}")

    def open_report_dialog(self):
        selected = self.record_tree.currentItem()
        if selected is None:
            QMessageBox.information(self, "선택 필요", "리포트로 볼 진단/조치 항목을 선택하세요.")
            return

        payload = selected.data(0, Qt.UserRole)
        if not isinstance(payload, dict):
            QMessageBox.information(self, "안내", "날짜 노드는 리포트를 표시하지 않습니다.")
            return

        dialog = ReportDialog(payload, self)
        dialog.exec_()


def main():
    app = QApplication(sys.argv)
    win = MainWindow()
    win.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
