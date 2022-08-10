import sys
from PyQt5.QtWidgets import *    
from PyQt5.QtGui import *
from PyQt5.QtCore import Qt
from cryptography.fernet import Fernet
import pandas as pd
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import csv
import pyperclip

class MainWindow(QMainWindow):
    def __init__(self, parent=None):
        super(MainWindow, self).__init__(parent)
        self.setWindowTitle("bru.exe")
        self.setFont(QFont("Comic Sans MS", 10))
        self.scene = QStackedWidget()
        self.setCentralWidget(self.scene)

        if os.path.exists("secretformula.csv"):
            self.switchWidget(Login(self))
        else:
            self.switchWidget(FirstTime(self))

    def createPassword(self):
        oneString = self.scene.currentWidget().oneLineEdit.text()
        twoString = self.scene.currentWidget().twoLineEdit.text()

        try:
            oneString.encode(encoding = 'UTF-8', errors = 'strict')
            twoString.encode(encoding = 'UTF-8', errors = 'strict')
        except:
            self.scene.currentWidget().errorLabel.setText("Invalid Characters")
            

        if (oneString != twoString):
            self.scene.currentWidget().errorLabel.setText("Passwords Do Not Match")
            self.scene.currentWidget().errorLabel.show()
        else:
            key = createCSV(oneString)
            decryptCSV(key)
            self.switchWidget(PasswordView(key, self))
            self.scrollbar()
            encryptCSV(key)

    def checkPassword(self):
        password = self.scene.currentWidget().passwordLineEdit.text()
        key = generateKey(password)

        if (decryptCSV(key)):
            self.switchWidget(PasswordView(key, self))
            self.scrollbar()
            encryptCSV(key)
        else:
            self.scene.currentWidget().errorLabel.setText("Incorrect Password")
            self.scene.currentWidget().errorLabel.show()

    def switchWidget(self, widget):
        self.scene.addWidget(widget)
        self.scene.setCurrentWidget(widget)

    def scrollbar(self):
        self.scroll = QScrollArea(self)
        self.scroll.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOn)
        self.scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.scroll.setWidgetResizable(True)
        self.scroll.setWidget(self.scene.currentWidget())
        self.scene.addWidget(self.scroll)
        self.scene.setCurrentWidget(self.scroll)

class FirstTime(QDialog) :
    def __init__(self, parent=None):
        super(FirstTime, self).__init__(parent)
        self.initUI()

    def initUI(self):
        self.introLabel = QLabel(self)
        self.introLabel.setText("Welcome! Please enter a password which will act as a master password to all of your other passwords.")

        self.oneLabel = QLabel(self)
        self.oneLabel.setText("Password: ")
        self.oneLineEdit = QLineEdit(self)
        self.oneLabel.setBuddy(self.oneLineEdit)

        self.twoLabel = QLabel(self)
        self.twoLabel.setText("Re-Enter Password: ")
        self.twoLineEdit = QLineEdit(self)
        self.twoLabel.setBuddy(self.twoLineEdit)

        self.okButton = QPushButton("OK", self)
        self.okButton.clicked.connect(self.parent().createPassword)

        self.errorLabel = QLabel(self)
        self.errorLabel.hide()

        self.gridLayout = QGridLayout(self)
        self.gridLayout.addWidget(self.introLabel, 0, 0, 1, 2, Qt.AlignCenter)
        self.gridLayout.addWidget(self.oneLabel, 1, 0)
        self.gridLayout.addWidget(self.oneLineEdit, 1, 1)
        self.gridLayout.addWidget(self.twoLabel, 2, 0)
        self.gridLayout.addWidget(self.twoLineEdit, 2, 1)
        self.gridLayout.addWidget(self.okButton, 3, 0, 1, 2, Qt.AlignCenter)
        self.gridLayout.addWidget(self.errorLabel, 4, 0, 1, 2, Qt.AlignCenter)

class Login(QDialog) :
    def __init__(self, parent = None):
        super(Login, self).__init__(parent)
        self.initUI()

    def initUI(self):
        self.passwordLabel = QLabel(self)
        self.passwordLabel.setText("Password: ")
        self.passwordLineEdit = QLineEdit(self)
        self.passwordLineEdit.setEchoMode(QLineEdit.EchoMode.Password)
        self.passwordLabel.setBuddy(self.passwordLineEdit)

        self.enterButton = QPushButton("ENTER", self)
        self.enterButton.clicked.connect(self.parent().checkPassword)

        self.errorLabel = QLabel(self)
        self.errorLabel.hide()

        self.gridLayout = QGridLayout(self)
        self.gridLayout.addWidget(self.passwordLabel, 0, 0)
        self.gridLayout.addWidget(self.passwordLineEdit, 0, 1)
        self.gridLayout.addWidget(self.enterButton, 1, 0, 1, 2, Qt.AlignCenter)
        self.gridLayout.addWidget(self.errorLabel, 2, 0, 1, 2, Qt.AlignCenter)
    


class PasswordView(QWidget):
    def __init__(self, key: bytes, parent = None):
        super(PasswordView, self).__init__(parent)
        self.initUI()
        self.key = key

    def initUI(self):
        self.grey = False
        self.vbox = QVBoxLayout(self)
        
        self.serviceLabel = QLabel(self)
        self.serviceLabel.setText("Service: ")
        self.serviceLineEdit = QLineEdit(self)
        self.serviceLabel.setBuddy(self.serviceLineEdit)

        self.usernameLabel = QLabel(self)
        self.usernameLabel.setText("Username: ")
        self.usernameLineEdit = QLineEdit(self)
        self.usernameLabel.setBuddy(self.usernameLineEdit)

        self.passwordLabel = QLabel(self)
        self.passwordLabel.setText("Password: ")
        self.passwordLineEdit = QLineEdit(self)
        self.passwordLabel.setBuddy(self.passwordLineEdit)

        self.createRowButton = QPushButton(self)
        self.createRowButton.setText("ADD")
        self.createRowButton.clicked.connect(self.createNewRow)

        self.inputHBox = QHBoxLayout()
        self.inputHBox.addWidget(self.serviceLabel)
        self.inputHBox.addWidget(self.serviceLineEdit)
        self.inputHBox.addWidget(self.usernameLabel)
        self.inputHBox.addWidget(self.usernameLineEdit)
        self.inputHBox.addWidget(self.passwordLabel)
        self.inputHBox.addWidget(self.passwordLineEdit)
        self.inputHBox.addWidget(self.createRowButton)

        self.searchLabel = QLabel(self)
        self.searchLabel.setText("Search: ")

        self.searchLineEdit = QLineEdit(self)
        self.searchLineEdit.textChanged.connect(self.redisplay)
        self.searchLineEdit.setMaximumWidth(500)
        self.searchLabel.setBuddy(self.searchLineEdit)

        self.searchHBox = QHBoxLayout()
        self.searchHBox.addWidget(self.searchLabel)
        self.searchHBox.addWidget(self.searchLineEdit)
        self.searchHBox.addStretch()

        self.vbox.addLayout(self.inputHBox)
        self.vbox.addLayout(self.searchHBox)

        df = pd.read_csv('secretformula.csv')
        self.generateRow(df.columns.values, True)
        df.apply(self.generateRow, axis = 1)

        self.setLayout(self.vbox)

    
    def generateRow(self, row : list, green : bool = False):
        hbox = QHBoxLayout()

        serviceButton = QPushButton(row[0])
        serviceButton.clicked.connect(lambda:copyToClipBoard(serviceButton.text()))
        serviceButton.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.setStyle(serviceButton, green)

        usernameButton = QPushButton(row[1])
        usernameButton.clicked.connect(lambda:copyToClipBoard(usernameButton.text()))
        usernameButton.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.setStyle(usernameButton, green)

        passwordButton = QPushButton(row[2])
        passwordButton.clicked.connect(lambda:copyToClipBoard(passwordButton.text()))
        passwordButton.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.setStyle(passwordButton, green)

        if (green):
            button1 = QPushButton("EDIT")
            customHide(button1, True)
            button2 = QPushButton("DELETE")
            customHide(button2, True)
            hbox.addWidget(serviceButton)
            hbox.addWidget(usernameButton)
            hbox.addWidget(passwordButton)
            hbox.addWidget(button1)
            hbox.addWidget(button2)
            self.vbox.addLayout(hbox)
            return

        serviceLineEdit = QLineEdit()
        usernameLineEdit = QLineEdit()
        passwordLineEdit = QLineEdit()

        serviceLineEdit.hide()
        usernameLineEdit.hide()
        passwordLineEdit.hide()

        deleteButton = QPushButton("DELETE")
        yesButton = QPushButton("YES")
        noButton = QPushButton("NO")
        editButton = QPushButton("EDIT")
        confirmButton = QPushButton("CONFIRM")
        cancelButton = QPushButton("CANCEL")
        
        yesButton.hide()
        noButton.hide()
        confirmButton.hide()
        cancelButton.hide()

        deleteButton.clicked.connect(lambda:self.deleteButtonFunction(deleteButton, yesButton, noButton, editButton))
        noButton.clicked.connect(lambda:self.noButtonFunction(deleteButton, yesButton, noButton, editButton))
        yesButton.clicked.connect(lambda:self.yesButtonFunction(hbox))
        editButton.clicked.connect(lambda:self.editButtonFunction(serviceButton, usernameButton, passwordButton, serviceLineEdit, usernameLineEdit, passwordLineEdit, editButton, cancelButton, confirmButton, deleteButton))
        cancelButton.clicked.connect(lambda:self.cancelButtonFunction(serviceButton, usernameButton, passwordButton, serviceLineEdit, usernameLineEdit, passwordLineEdit, editButton, cancelButton, confirmButton, deleteButton))
        confirmButton.clicked.connect(lambda:self.confirmButtonFunction(serviceButton, usernameButton, passwordButton, serviceLineEdit, usernameLineEdit, passwordLineEdit, editButton, cancelButton, confirmButton, deleteButton))

        hbox.addWidget(serviceButton)
        hbox.addWidget(usernameButton)
        hbox.addWidget(passwordButton)
        hbox.addWidget(serviceLineEdit)
        hbox.addWidget(usernameLineEdit)
        hbox.addWidget(passwordLineEdit)
        hbox.addWidget(editButton)
        hbox.addWidget(deleteButton)
        hbox.addWidget(yesButton)
        hbox.addWidget(noButton)
        hbox.addWidget(cancelButton)
        hbox.addWidget(confirmButton)

        self.vbox.addLayout(hbox)
        self.grey = not self.grey

    def createNewRow(self):
        service = self.serviceLineEdit.text()
        username = self.usernameLineEdit.text()
        password = self.passwordLineEdit.text()

        if (service and username and password):
            decryptCSV(self.key)
            with open('secretformula.csv', 'a', newline='') as f:
                writer = csv.writer(f)
                writer.writerow([service, username, password])
            encryptCSV(self.key)

            self.generateRow([service, username, password])

            self.serviceLineEdit.setText("")
            self.usernameLineEdit.setText("")
            self.passwordLineEdit.setText("")

    def redisplay(self):
        self.grey = False
        for i in range(3, self.vbox.count()):
            if (self.searchLineEdit.text().lower() in self.vbox.itemAt(i).itemAt(0).widget().text().lower()):
                for j in range(0, 3):
                    self.vbox.itemAt(i).itemAt(j).widget().show()
                    self.setStyle(self.vbox.itemAt(i).itemAt(j).widget())
                for j in range(3, 6):
                    self.vbox.itemAt(i).itemAt(j).widget().hide()
                for j in range(6, 8):
                    self.vbox.itemAt(i).itemAt(j).widget().show()
                for j in range(8, 12):
                    self.vbox.itemAt(i).itemAt(j).widget().hide()
                self.grey = not self.grey
            else:
                for j in range(0, 12):
                    self.vbox.itemAt(i).itemAt(j).widget().hide()

    def setStyle(self, button : QPushButton, green : bool = False):
        if (green):
            button.setStyleSheet("background-color:green; color:white; font-family: \"Comic Sans MS\", \"Comic Sans\"; font-size:18px;")
        elif (self.grey):
            button.setStyleSheet("background-color:#808080; color:white; font-family: \"Comic Sans MS\", \"Comic Sans\"; font-size:18px;")
        else:
            button.setStyleSheet("background-color:#A9A9A9; color:white; font-family: \"Comic Sans MS\", \"Comic Sans\"; font-size:18px;")

    def deleteButtonFunction(self, deleteButton : QPushButton, yesButton : QPushButton, noButton : QPushButton, editButton : QPushButton):
        editButton.hide()
        deleteButton.hide()
        yesButton.show()
        noButton.show()
        

    def noButtonFunction(self, deleteButton : QPushButton, yesButton : QPushButton, noButton : QPushButton, editButton : QPushButton):
        yesButton.hide()
        noButton.hide()
        editButton.show()
        deleteButton.show()
        
    def yesButtonFunction(self, row : QHBoxLayout):
        for i in range(row.count()):
            row.itemAt(i).widget().deleteLater()
        self.vbox.removeItem(row)
        self.updateCSV()
        self.redisplay()

    def editButtonFunction(self, serviceButton : QPushButton, usernameButton : QPushButton, passwordButton : QPushButton, serviceLineEdit : QLineEdit, usernameLineEdit : QLineEdit, passwordLineEdit : QLineEdit, editButton : QPushButton, cancelButton : QPushButton, confirmButton : QPushButton, deleteButton : QPushButton):
        serviceButton.hide()
        usernameButton.hide()
        passwordButton.hide()
        serviceLineEdit.setText(serviceButton.text())
        usernameLineEdit.setText(usernameButton.text())
        passwordLineEdit.setText(passwordButton.text())
        serviceLineEdit.show()
        usernameLineEdit.show()
        passwordLineEdit.show()
        editButton.hide()
        deleteButton.hide()
        cancelButton.show()
        confirmButton.show()

    def cancelButtonFunction(self, serviceButton : QPushButton, usernameButton : QPushButton, passwordButton : QPushButton, serviceLineEdit : QLineEdit, usernameLineEdit : QLineEdit, passwordLineEdit : QLineEdit, editButton : QPushButton, cancelButton : QPushButton, confirmButton : QPushButton, deleteButton : QPushButton):
        serviceLineEdit.hide()
        usernameLineEdit.hide()
        passwordLineEdit.hide()
        serviceButton.show()
        usernameButton.show()
        passwordButton.show()
        cancelButton.hide()
        confirmButton.hide()
        editButton.show()
        deleteButton.show()

    def confirmButtonFunction(self, serviceButton : QPushButton, usernameButton : QPushButton, passwordButton : QPushButton, serviceLineEdit : QLineEdit, usernameLineEdit : QLineEdit, passwordLineEdit : QLineEdit, editButton : QPushButton, cancelButton : QPushButton, confirmButton : QPushButton, deleteButton : QPushButton):
        serviceButton.setText(serviceLineEdit.text())
        usernameButton.setText(usernameLineEdit.text())
        passwordButton.setText(passwordLineEdit.text())
        serviceLineEdit.hide()
        usernameLineEdit.hide()
        passwordLineEdit.hide()
        serviceButton.show()
        usernameButton.show()
        passwordButton.show()
        cancelButton.hide()
        confirmButton.hide()
        editButton.show()
        deleteButton.show()
        self.updateCSV()

    def updateCSV(self):
        with open('secretformula.csv', 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(["Service", "Username", "Password"])
            for i in range(3, self.vbox.count()):
                writer.writerow([self.vbox.itemAt(i).itemAt(0).widget().text(), self.vbox.itemAt(i).itemAt(1).widget().text(), self.vbox.itemAt(i).itemAt(2).widget().text()])
        encryptCSV(self.key)
        

def createCSV(password : str):
    with open('secretformula.csv', 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(["Service", "Username", "Password"])

    salt = os.urandom(16)
    with open('salt.txt', 'wb') as f:
        f.write(salt)
    key = generateKey(password)
    encryptCSV(key)
    return key

def decryptCSV(key: bytes):
    fernet = Fernet(key)
    with open('secretformula.csv', 'rb') as f:
        encrypted = f.read()

    try:
        decrypted = fernet.decrypt(encrypted)
    except:
        return False

    with open('secretformula.csv', 'wb') as f:
        f.write(decrypted)

    return True

def encryptCSV(key: bytes):
    fernet = Fernet(key)

    with open('secretformula.csv', 'rb') as f:
        decrypted = f.read()

    encrypted = fernet.encrypt(decrypted)

    with open('secretformula.csv', 'wb') as f:
        f.write(encrypted)

def getSalt():
    with open('salt.txt', 'rb') as f:
        return f.read()

def generateKey(password : str):
    salt = getSalt()
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=480000)
    key = base64.urlsafe_b64encode(kdf.derive(bytes(password, 'utf-8')))
    return key

def copyToClipBoard(text : str):
    pyperclip.copy(text)

def customHide(button : QPushButton, inPlace : bool = False):
    sp = button.sizePolicy()
    sp.setRetainSizeWhenHidden(inPlace)
    button.setSizePolicy(sp)
    button.hide()    

if __name__ == '__main__':
    app = QApplication([])
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())
