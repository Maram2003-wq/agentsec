# 🔒 AgentSec Scanner

Scanner de vulnérabilités automatisé combinant **n8n** (orchestration) et **Flask** (interface web).

## 🏗️ Architecture

Utilisateur → Flask (port 3000) → n8n Webhook (port 5678) → Nmap / Nikto / Groq AI → Rapport PDF
## 📋 Prérequis

| Outil | Version testée | Installation |
|---|---|---|
| Python | 3.10+ | `sudo apt install python3` |
| pip | 23+ | `sudo apt install python3-pip` |
| Node.js | 18+ | `sudo apt install nodejs` |
| npm | 9+ | `sudo apt install npm` |
| n8n | 1.x | `npm install -g n8n` |
| Nmap | 7.80+ | `sudo apt install nmap` |
| Nikto | 2.1.6+ | `sudo apt install nikto` |
| WhatWeb | 0.5.5+ | `sudo apt install whatweb` |
| Gobuster | 3.x | `sudo apt install gobuster` |
| WPScan | 3.x | `gem install wpscan` |
| Hydra | 9.x | `sudo apt install hydra` |
| SSLScan | 2.x | `sudo apt install sslscan` |

## ⚙️ Installation
```bash
git clone https://github.com/Maram2003-wq/agentsec.git
cd agentsec
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## 🔑 Clé API Groq

1. Crée un compte sur https://console.groq.com
2. Génère une clé API
3. Dans n8n : Settings → Credentials → + Add → colle ta clé Groq

⚠️ Ne jamais écrire la clé dans les fichiers du projet

## 📧 Configuration SMTP (envoi d'email)

Le workflow n8n envoie automatiquement le rapport par email après chaque scan.
Pour activer cette fonctionnalité, tu dois configurer un serveur SMTP dans n8n.

### Option 1 — Gmail (recommandé)

1. Active la validation en 2 étapes sur ton compte Google
2. Va sur https://myaccount.google.com/apppasswords
3. Génère un **mot de passe d'application** (App Password)
4. Dans n8n : **Settings → Credentials → + Add Credential → SMTP**

| Champ | Valeur |
|---|---|
| Host | smtp.gmail.com |
| Port | 465 |
| SSL | ✅ Activé |
| User | ton.email@gmail.com |
| Password | le mot de passe d'application généré |

## 🚀 Lancement

⚠️ Ouvrir 2 terminaux séparés et lancer les 2 commandes en même temps.

### Terminal 1 — Lancer n8n
```bash
cd ~/agentsec && N8N_RUNNERS_TIMEOUT=120000 NODE_FUNCTION_ALLOW_BUILTIN=* NODE_FUNCTION_ALLOW_EXTERNAL=* npx n8n start
```

| Variable | Rôle |
|---|---|
| N8N_RUNNERS_TIMEOUT=120000 | Timeout à 120s pour les scans longs |
| NODE_FUNCTION_ALLOW_BUILTIN=* | Autorise les modules Node.js natifs |
| NODE_FUNCTION_ALLOW_EXTERNAL=* | Autorise les modules npm externes |

Puis dans n8n sur http://localhost:5678 :
1. Workflows → Import from file
2. Sélectionne workflow_complet.json
3. Active le workflow avec le toggle en haut à droite

### Terminal 2 — Lancer Flask
```bash
cd ~/agentsec && source venv/bin/activate && python launch_flask.py
```

| Commande | Rôle |
|---|---|
| cd ~/agentsec | Se placer dans le dossier du projet |
| source venv/bin/activate | Activer l'environnement Python virtuel |
| python launch_flask.py | Démarrer le serveur web Flask |

## 🌐 Accès

| Service | URL |
|---|---|
| Interface AgentSec | http://localhost:3000 |
| Interface n8n | http://localhost:5678 |

## 🔍 Outils de scan utilisés

| Outil | Rôle |
|---|---|
| Nmap | Découverte des ports ouverts et services |
| Nikto | Détection de vulnérabilités web |
| SSLScan | Analyse de la configuration SSL/TLS |
| WhatWeb | Identification des technologies utilisées |
| Gobuster | Énumération des répertoires cachés |
| WPScan | Détection des vulnérabilités WordPress |
| Hydra | Test de mots de passe faibles |
| Groq AI | Analyse intelligente et recommandations |

## 📁 Structure du projet
agentsec/
├── app.py                           # Serveur Flask principal
├── launch_flask.py                  # Script de démarrage Flask
├── database.py                      # Gestion base de données
├── init_db.py                       # Initialisation BDD
├── agent.json                       # Workflow n8n simplifié
├── workflow_complet.json            # Workflow n8n complet
├── n8n_consolidation_workflow.json  # Workflow de consolidation
├── templates/
│   ├── index.html                   # Interface principale
│   └── consolidation.html           # Page de consolidation
└── .gitignore                       # Exclut venv, .env, pycache

## ⚠️ Avertissement légal

Cet outil est destiné uniquement à des fins **éducatives** et de tests sur des systèmes dont vous êtes propriétaire ou pour lesquels vous avez une **autorisation explicite**. Toute utilisation non autorisée est illégale.

## 👩‍💻 Auteur

Développé par **Maram** — Projet de cybersécurité AgentSec
