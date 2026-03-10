# ===========================
#   Makefile pentru proiectul ElGamal ECC
#   Autor: ChatGPT
# ===========================

# Localizare fișiere sursă și destinație build
SRC_DIR = src
OUT_DIR = out

# Pachetul principal
MAIN_CLASS = com.example.eccelgamal.ElGamalEccDemo

# JAR-ul Bouncy Castle instalat via apt
BC_JAR = /usr/share/java/bcprov.jar

# Găsește toate fișierele .java din src/
SOURCES := $(shell find $(SRC_DIR) -name "*.java")

# Target implicit = build
all: build

# ===========================
# Compilare
# ===========================
build:
	@echo "==> Compiling Java project..."
	@mkdir -p $(OUT_DIR)
	javac -cp $(BC_JAR) -d $(OUT_DIR) $(SOURCES)
	@echo "==> Build completed."

# ===========================
# Rulare clasă principală
# ===========================
run: build
	@echo "==> Running ElGamal ECC Demo..."
	java -cp $(OUT_DIR):$(BC_JAR) $(MAIN_CLASS)

# ===========================
# Curățare fișiere compilate
# ===========================
clean:
	@echo "==> Cleaning build directory..."
	rm -rf $(OUT_DIR)
	@echo "==> Clean completed."

# ===========================
# Rulează orice clasă din proiect
# Ex: make exec CLASS=com.example.Test
# ===========================
exec:
	@if [ -z "$(CLASS)" ]; then \
		echo "Use: make exec CLASS=com.example.MyClass"; \
	else \
		java -cp $(OUT_DIR):$(BC_JAR) $(CLASS); \
	fi

