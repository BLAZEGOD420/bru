import sys
from PyQt5.QtWidgets import *    
from PyQt5.QtGui import *
from PyQt5.QtCore import Qt, QTimer
from cryptography.fernet import Fernet
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import csv
import pyperclip

basedir = os.path.dirname(__file__)

class PasswordButton(QPushButton):
    def __init__(self, password: str, text: str = "*****"):
        super().__init__(text)
        self.key = password

    def password(self) -> str:
        return self.key
    
    def setPassword(self, password: str):
        self.key = password

class MainWindow(QMainWindow):
    def __init__(self, parent=None):
        super(MainWindow, self).__init__(parent)
        self.setWindowTitle("bru")
        self.setFont(QFont("Inter", 10))
        self.scene = QStackedWidget()
        self.setCentralWidget(self.scene)

        if os.path.exists(os.path.join(basedir, 'secretformula.csv')):
            self.switchWidget(Login(self))
        else:
            self.switchWidget(FirstTime(self))

    def createPassword(self):
        oneString = self.scene.currentWidget().oneLineEdit.text()
        twoString = self.scene.currentWidget().twoLineEdit.text()

        # not sure if this even matters, python seems to convert it into a UTF character regardless if its in a string
        try:
            oneString.encode(encoding = 'UTF-8', errors = 'strict')
            twoString.encode(encoding = 'UTF-8', errors = 'strict')
        except:
            self.scene.currentWidget().errorLabel.setText("Invalid Characters")
            
        if (len(oneString) == 0):
            self.showErrorMessage("Please Enter a Password")
        elif (len(twoString) == 0):
            self.showErrorMessage("Please Re-Enter the Password")
        elif (oneString != twoString):
            self.showErrorMessage("Passwords Do Not Match")
        else:
            key = createCSV(oneString)
            decryptCSV(key)
            try:
                self.switchWidget(PasswordView(key, self))
                self.scrollbar()
            except:
                self.showErrorMessage("ERROR: Application Failed to Load")
            finally:encryptCSV(key)

    def checkPassword(self):
        password = self.scene.currentWidget().passwordLineEdit.text()
        key = generateKey(password)

        if (decryptCSV(key)):
            try:
                self.switchWidget(PasswordView(key, self))
                self.scrollbar()
            except:
                self.showErrorMessage("ERROR: Password was Correct, but Application Failed to Load")
            finally:
                encryptCSV(key)
        else:
            self.showErrorMessage("Incorrect Password")

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

    def showErrorMessage(self, message: str, timeout: int = 2000):
        self.scene.currentWidget().errorLabel.setText(message)
        self.scene.currentWidget().errorLabel.show()
        self.scene.currentWidget().setTimeout(timeout)

class FirstTime(QDialog) :
    def __init__(self, parent=None):
        super(FirstTime, self).__init__(parent)
        self.initUI()

    def initUI(self):
        vbox = QVBoxLayout(self)
        vbox.setAlignment(Qt.AlignTop)

        self.timer = QTimer(self)

        introLabel = QLabel()
        introLabel.setText("Welcome! Please enter a password which will act as a master password to all of your other passwords.")
        introLabel.setContentsMargins(0, 0, 0, 50)

        oneLabel = QLabel()
        oneLabel.setText("Password: ")
        self.oneLineEdit = QLineEdit()
        oneLabel.setBuddy(self.oneLineEdit)

        twoLabel = QLabel()
        twoLabel.setText("Re-Enter Password: ")
        self.twoLineEdit = QLineEdit()
        twoLabel.setBuddy(self.twoLineEdit)

        okButton = QPushButton("OK")
        okButton.clicked.connect(self.parent().createPassword)

        self.errorLabel = QLabel()
        self.errorLabel.setContentsMargins(0, 100, 0, 0)
        self.errorLabel.hide()

        grid = QGridLayout()
        grid.addWidget(oneLabel, 0, 0)
        grid.addWidget(self.oneLineEdit, 0, 1)
        grid.addWidget(twoLabel, 1, 0)
        grid.addWidget(self.twoLineEdit, 1, 1)

        vbox.addWidget(introLabel, alignment=Qt.AlignCenter)
        vbox.addLayout(grid)
        vbox.addWidget(okButton, alignment=Qt.AlignCenter)
        vbox.addWidget(self.errorLabel, alignment=Qt.AlignCenter)
        
    def hideErrorLabel(self):
        self.errorLabel.hide()

    def setTimeout(self, timeout: int):
        self.timer.setInterval(timeout)
        self.timer.timeout.connect(self.hideErrorLabel)
        self.timer.start()

class Login(QDialog) :
    def __init__(self, parent = None):
        super(Login, self).__init__(parent)
        self.initUI()

    def initUI(self):
        vbox = QVBoxLayout(self)
        vbox.setAlignment(Qt.AlignTop)

        hbox = QHBoxLayout()

        passwordLabel = QLabel()
        passwordLabel.setText("Password: ")
        self.passwordLineEdit = QLineEdit()
        self.passwordLineEdit.setEchoMode(QLineEdit.EchoMode.Password)
        passwordLabel.setBuddy(self.passwordLineEdit)

        enterButton = QPushButton("ENTER")
        enterButton.clicked.connect(self.parent().checkPassword)

        self.errorLabel = QLabel()
        self.errorLabel.hide()
        
        self.timer = QTimer(self)

        hbox.addWidget(passwordLabel)
        hbox.addWidget(self.passwordLineEdit)
        hbox.addWidget(enterButton)
        hbox.setContentsMargins(0, 0, 0, 100)

        vbox.addLayout(hbox)
        vbox.addWidget(self.errorLabel, alignment=Qt.AlignCenter)

    def hideErrorLabel(self):
        self.errorLabel.hide()

    def setTimeout(self, timeout: int):
        self.timer.setInterval(timeout)
        self.timer.timeout.connect(self.hideErrorLabel)
        self.timer.start()


class PasswordView(QWidget):
    def __init__(self, key: bytes, parent = None):
        super(PasswordView, self).__init__(parent)
        self.initUI()
        self.key = key

    def initUI(self):
        self.grey = False
        self.vbox = QVBoxLayout(self)
        self.vbox.setAlignment(Qt.AlignTop)

        self.menu = self.parent().menuBar()
        fileMenu = self.menu.addMenu("&File")
        importAction = QAction("&Import from CSV", self)
        importAction.triggered.connect(self.importFromCSV)
        exportAction = QAction("&Export to CSV", self)
        exportAction.triggered.connect(self.exportToCSV)
        fileMenu.addAction(importAction)
        fileMenu.addAction(exportAction)

        serviceLabel = QLabel("Service: ")
        self.serviceLineEdit = QLineEdit()
        serviceLabel.setBuddy(self.serviceLineEdit)

        usernameLabel = QLabel("Username: ")
        self.usernameLineEdit = QLineEdit()
        usernameLabel.setBuddy(self.usernameLineEdit)

        passwordLabel = QLabel("Password: ")
        self.passwordLineEdit = QLineEdit()
        passwordLabel.setBuddy(self.passwordLineEdit)

        createRowButton = QPushButton("ADD")
        createRowButton.clicked.connect(self.createNewRow)

        inputHBox = QHBoxLayout()
        inputHBox.addWidget(serviceLabel)
        inputHBox.addWidget(self.serviceLineEdit)
        inputHBox.addWidget(usernameLabel)
        inputHBox.addWidget(self.usernameLineEdit)
        inputHBox.addWidget(passwordLabel)
        inputHBox.addWidget(self.passwordLineEdit)
        inputHBox.addWidget(createRowButton)

        searchLabel = QLabel("Search: ")
        self.searchLineEdit = QLineEdit(self)
        self.searchLineEdit.textChanged.connect(self.redisplay)
        spacer = QSpacerItem(self.window().width() // 5, 0)
        searchLabel.setBuddy(self.searchLineEdit)

        searchHBox = QHBoxLayout()
        searchHBox.addWidget(searchLabel)
        searchHBox.addWidget(self.searchLineEdit)
        searchHBox.addSpacerItem(spacer)
        searchHBox.setContentsMargins(0, 0, 0, 30)

        self.vbox.addLayout(inputHBox)
        self.vbox.addLayout(searchHBox)

        self.generateHeader()

        try:
            self.loadPasswords()
        except:
            pass

        self.setLayout(self.vbox)

    def generateHeader(self):
        hbox = QHBoxLayout()
        serviceHeader = QLabel("Service")
        serviceHeader.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        serviceHeader.setAlignment(Qt.AlignCenter)
        self.setStyle(serviceHeader, True)

        usernameHeader = QLabel("Username")
        usernameHeader.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        usernameHeader.setAlignment(Qt.AlignCenter)
        self.setStyle(usernameHeader, True)

        passwordHeader = QLabel("Password")
        passwordHeader.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        passwordHeader.setAlignment(Qt.AlignCenter)
        self.setStyle(passwordHeader, True)

        button1 = QPushButton("  EDIT  ")
        customHide(button1, True)
        button2 = QPushButton(" DELETE  ")
        customHide(button2, True)
        hbox.addWidget(serviceHeader)
        hbox.addWidget(usernameHeader)
        hbox.addWidget(passwordHeader)
        hbox.addWidget(button1)
        hbox.addWidget(button2)

        hbox.setContentsMargins(0, 0, 0, 10)
        self.vbox.addLayout(hbox)

    def generateRow(self, row : list):
        hbox = QHBoxLayout()

        serviceButton = QPushButton(row[0])
        serviceButton.clicked.connect(lambda:copyToClipBoard(serviceButton.text()))
        serviceButton.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.setStyle(serviceButton)

        usernameButton = QPushButton(row[1])
        usernameButton.clicked.connect(lambda:copyToClipBoard(usernameButton.text()))
        usernameButton.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.setStyle(usernameButton)

        passwordButton = PasswordButton(row[2])
        passwordButton.clicked.connect(lambda:copyToClipBoard(passwordButton.password()))
        passwordButton.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.setStyle(passwordButton)

        serviceLineEdit = QLineEdit()
        usernameLineEdit = QLineEdit()
        passwordLineEdit = QLineEdit()

        serviceLineEdit.hide()
        usernameLineEdit.hide()
        passwordLineEdit.hide()

        deleteButton = QPushButton(" DELETE  ")
        yesButton = QPushButton("   YES   ")
        noButton = QPushButton("     NO     ")
        editButton = QPushButton("  EDIT  ")
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

        # not sure if this even matters, python seems to convert it into a UTF character regardless if its in a string
        try:
            service.encode(encoding = 'UTF-8', errors = 'strict')
            username.encode(encoding = 'UTF-8', errors = 'strict')
            password.encode(encoding = 'UTF-8', errors = 'strict')
        except:
            QMessageBox.warning(self, "Warning", "Cannot accept non UTF-8 characters.")

        if (service and username and password):
            self.writeRow([service, username, password])
            self.generateRow([service, username, password])

            self.serviceLineEdit.setText("")
            self.usernameLineEdit.setText("")
            self.passwordLineEdit.setText("")

    def writeRow(self, row: list):
        decryptCSV(self.key)
        with open(os.path.join(basedir, 'secretformula.csv'), 'a', encoding='utf-8', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([row[0], row[1], row[2]])
        encryptCSV(self.key)        
        
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

    def setStyle(self, widget : QWidget, green : bool = False):
        
        if (green):
            widget.setFont(QFont('Inter', 12, weight=100))
        elif (self.grey):
            palette = widget.palette()
            palette.setColor(QPalette.Button, QColor('#A9A9A9'))
            palette.setBrush(QPalette.ButtonText, QColor('white'))
            widget.setAutoFillBackground(True)
            widget.setPalette(palette)
            widget.update()
        else:
            widget.setFont(QFont('Inter', 10))

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

    def editButtonFunction(self, serviceButton : QPushButton, usernameButton : QPushButton, passwordButton : PasswordButton, serviceLineEdit : QLineEdit, usernameLineEdit : QLineEdit, passwordLineEdit : QLineEdit, editButton : QPushButton, cancelButton : QPushButton, confirmButton : QPushButton, deleteButton : QPushButton):
        serviceButton.hide()
        usernameButton.hide()
        passwordButton.hide()
        serviceLineEdit.setText(serviceButton.text())
        usernameLineEdit.setText(usernameButton.text())
        passwordLineEdit.setText(passwordButton.password())
        serviceLineEdit.show()
        usernameLineEdit.show()
        passwordLineEdit.show()
        editButton.hide()
        deleteButton.hide()
        cancelButton.show()
        confirmButton.show()

    def cancelButtonFunction(self, serviceButton : QPushButton, usernameButton : QPushButton, passwordButton : PasswordButton, serviceLineEdit : QLineEdit, usernameLineEdit : QLineEdit, passwordLineEdit : QLineEdit, editButton : QPushButton, cancelButton : QPushButton, confirmButton : QPushButton, deleteButton : QPushButton):
        serviceLineEdit.hide()
        usernameLineEdit.hide()
        passwordLineEdit.hide()
        serviceButton.show()
        usernameButton.show()
        passwordButton.setText("*****")
        passwordButton.show()
        cancelButton.hide()
        confirmButton.hide()
        editButton.show()
        deleteButton.show()

    def confirmButtonFunction(self, serviceButton : QPushButton, usernameButton : QPushButton, passwordButton : PasswordButton, serviceLineEdit : QLineEdit, usernameLineEdit : QLineEdit, passwordLineEdit : QLineEdit, editButton : QPushButton, cancelButton : QPushButton, confirmButton : QPushButton, deleteButton : QPushButton):
        service = serviceLineEdit.text()
        username = usernameLineEdit.text()
        password = passwordLineEdit.text()

        # not sure if this even matters, python seems to convert it into a UTF character regardless if its in a string
        try:
            service.encode(encoding = 'UTF-8', errors = 'strict')
            username.encode(encoding = 'UTF-8', errors = 'strict')
            password.encode(encoding = 'UTF-8', errors = 'strict')
        except:
            QMessageBox.warning(self, "Warning", "Cannot accept non UTF-8 characters.")
            serviceLineEdit.setText("")
            usernameLineEdit.setText("")
            passwordLineEdit.setText("")

        if (service and username and password):
            serviceButton.setText(service)
            usernameButton.setText(username)
            passwordButton.setPassword(password)
            passwordButton.setText("*****")
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

    def loadPasswords(self):
        with open(os.path.join(basedir, 'secretformula.csv'), 'r', encoding='utf-8') as f:
            reader = csv.reader(f)
            for row in reader:
                self.generateRow(row)

    def updateCSV(self):
        with open(os.path.join(basedir, 'secretformula.csv'), 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            for i in range(3, self.vbox.count()):
                writer.writerow([self.vbox.itemAt(i).itemAt(0).widget().text(), self.vbox.itemAt(i).itemAt(1).widget().text(), self.vbox.itemAt(i).itemAt(2).widget().password()])
        encryptCSV(self.key)

    def importFromCSV(self):
        file = QFileDialog.getOpenFileName(self, 'Select a File', filter="Comma Separated Value (*.csv)")[0]
        try:
            with open(os.path.join(basedir, file), 'r', newline='', encoding='utf-8') as f:
                reader = csv.reader(f)
                for row in reader:
                    if (len(row) >= 3 and row[0] and row[1] and row[2]):
                        self.writeRow(row)
                        self.generateRow(row)
        except:
            QMessageBox.warning(self, "Error", "Could not read csv file, check that it does not contain non UTF-8 characters.")
    
    def exportToCSV(self):
        file = QFileDialog.getSaveFileName(self, 'Select or Create a File', filter="Comma Separated Value (*.csv)")[0]

        try:
            with open(os.path.join(basedir, file), 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                for i in range(3, self.vbox.count()):
                    writer.writerow([self.vbox.itemAt(i).itemAt(0).widget().text(), self.vbox.itemAt(i).itemAt(1).widget().text(), self.vbox.itemAt(i).itemAt(2).widget().password()])
        except:
            pass
        

def createCSV(password : str):
    with open(os.path.join(basedir, 'secretformula.csv'), 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)

    salt = os.urandom(16)
    with open(os.path.join(basedir, 'salt.txt'), 'wb') as f:
        f.write(salt)

    key = generateKey(password)
    encryptCSV(key)
    return key

def decryptCSV(key: bytes):
    fernet = Fernet(key)
    with open(os.path.join(basedir, 'secretformula.csv'), 'rb') as f:
        encrypted = f.read()

    try:
        decrypted = fernet.decrypt(encrypted)
    except:
        return False

    with open(os.path.join(basedir, 'secretformula.csv'), 'wb') as f:
        f.write(decrypted)

    return True

def encryptCSV(key: bytes):
    fernet = Fernet(key)

    with open(os.path.join(basedir, 'secretformula.csv'), 'rb') as f:
        decrypted = f.read()

    encrypted = fernet.encrypt(decrypted)

    with open(os.path.join(basedir, 'secretformula.csv'), 'wb') as f:
        f.write(encrypted)

def getSalt():
    with open(os.path.join(basedir, 'salt.txt'), 'rb') as f:
        return f.read()

def generateKey(password : str):
    salt = getSalt()
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=480000)
    key = base64.urlsafe_b64encode(kdf.derive(bytes(password, 'utf-8')))
    return key

def copyToClipBoard(text : str):
    pyperclip.copy(text)

def customHide(widget : QWidget, inPlace : bool = False):
    sp = widget.sizePolicy()
    sp.setRetainSizeWhenHidden(inPlace)
    widget.setSizePolicy(sp)
    widget.hide()    

if __name__ == '__main__':

    try:
        from ctypes import windll
        myappid = 'bru.1.0'
        windll.shell32.SetCurrentProcessExplicitAppUserModelID(myappid)
    except ImportError:
        pass


    app = QApplication([])
    app.setStyle('Fusion')
    app.setWindowIcon(QIcon(os.path.join(basedir, 'icon.ico')))
    window = MainWindow()
    screen = app.primaryScreen()
    window.setMinimumWidth(screen.size().width() // 2)
    window.setMinimumHeight(screen.size().width() * 3 // 9)
    window.show()
    sys.exit(app.exec_())