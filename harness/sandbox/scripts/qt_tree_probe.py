#!/usr/bin/env python3
"""Empirically probe QTreeWidget signal/expansion behaviour offscreen.

Answers for the Proto Clean region-tree review:
1. Does clicking the branch (expand/collapse arrow) emit itemClicked?
   If yes, a manual toggle in the itemClicked handler would double-toggle
   and desync the expansion-state set.
2. Does double-clicking the row toggle expansion (expandsOnDoubleClick)
   AND emit itemDoubleClicked?
3. Does setExpanded(True) BEFORE children are added keep the item
   expanded once children appear?
"""
import os
import sys

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, "/home/z/my-project/cleanroom")

from proto_clean.qtcompat import (QApplication, QTreeWidget, QTreeWidgetItem,
                                  Qt)
from PySide6.QtTest import QTest
from PySide6.QtCore import Qt as Qt6, QPoint

app = QApplication([])

events: list[str] = []
tree = QTreeWidget()
tree.setColumnCount(2)
hdr = QTreeWidgetItem(["REGION", ""])
tree.addTopLevelItem(hdr)
tree.resize(400, 300)
tree.show()
app.processEvents()


def on_clicked(item, col):
    events.append(f"itemClicked(kind={item.data(0, Qt.UserRole)})")
    # mimic MainWindow._on_item_clicked region branch
    if item.data(0, Qt.UserRole) == "region":
        item.setExpanded(not item.isExpanded())


def on_dclicked(item, col):
    events.append("itemDoubleClicked")


def on_expanded(item):
    events.append("itemExpanded")


def on_collapsed(item):
    events.append("itemCollapsed")


tree.itemClicked.connect(on_clicked)
tree.itemDoubleClicked.connect(on_dclicked)
tree.itemExpanded.connect(on_expanded)
tree.itemCollapsed.connect(on_collapsed)

hdr.setData(0, Qt.UserRole, "region")

rect = tree.visualItemRect(hdr)
indent = tree.indentation()
arrow = QPoint(indent // 2, rect.center().y())
text = QPoint(rect.x() + indent + 20, rect.center().y())

print(f"indentation={indent} rect={rect} arrow_x={arrow.x()} text_x={text.x()}")

# ---- 1. click on the arrow (collapsed -> expanded natively?)
QTest.mouseClick(tree.viewport(), Qt6.LeftButton, Qt6.NoModifier, arrow)
app.processEvents()
print("after arrow click: expanded =", hdr.isExpanded(), "| events:", events)
events.clear()

# ---- 2. click on the text area
QTest.mouseClick(tree.viewport(), Qt6.LeftButton, Qt6.NoModifier, text)
app.processEvents()
print("after text click : expanded =", hdr.isExpanded(), "| events:", events)
events.clear()

# ---- 3. double-click on the text area
QTest.mouseDClick(tree.viewport(), Qt6.LeftButton, Qt6.NoModifier, text)
app.processEvents()
print("after dblclick   : expanded =", hdr.isExpanded(), "| events:", events)
events.clear()

# ---- 4. setExpanded before children, then add children
tree.clear()
events.clear()
hdr2 = QTreeWidgetItem(["REGION2", ""])
hdr2.setData(0, Qt.UserRole, "region")
tree.addTopLevelItem(hdr2)
hdr2.setExpanded(True)
child = QTreeWidgetItem(["child", ""])
hdr2.addChild(child)
app.processEvents()
print("expand-before-children: item.expanded =", hdr2.isExpanded(),
      "| childCount =", hdr2.childCount())
print("tree top-level expanded state:", hdr2.isExpanded())

# cleanup
tree.close()
app.processEvents()
print("PROBE DONE")
