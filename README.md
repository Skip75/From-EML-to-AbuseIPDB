# AbuseIPDB Report Script

Ce dépôt contient un script PowerShell interactif dédié à la **soumission d'adresses IP malveillantes** vers l'API AbuseIPDB via l'analyse automatisée de fichiers EML, ainsi qu'à la **consultation du statut** d'une IP.

## Table des matières

- [Fonctionnalités](#fonctionnalités)  
- [Prérequis](#prérequis)  
- [Limitations de l'API AbuseIPDB](#limitations-de-lapi-abuseipdb)  
- [Analyse intelligente des headers](#analyse-intelligente-des-headers)  
- [Détection de spoofing](#détection-de-spoofing)  
- [Vérifications implémentées](#vérifications-implémentées)  
- [Structure du script](#structure-du-script)  
- [Usage](#usage)

## Fonctionnalités

### 1. Soumission d'IP malveillante via fichier EML

- **Normalisation des headers** : fusion des lignes multi-lignes  
- **Filtrage intelligent** : ignore les "Received: from" avant "Authentication-Results" (serveurs de réception légitimes)  
- **Extraction d'IP** depuis 3 sources : Authentication-Results, Received-SPF, Received: from  
- **Détection de manipulation** : alerte si headers en double, sélection manuelle par l'utilisateur  
- **Analyse contextuelle SPF** : recommandation automatique selon spf=pass/fail  
- **Suggestion des catégories** : analyse SPF + comparaison domaines → 7 (Phishing), 11 (Spam), 17 (Spoofing)  
- **Exclusion de mots sensibles** : remplacement par "username" dans les headers  
- **Timestamp personnalisé** : extraction depuis "Received: from" (format ISO 8601)  
- **Commentaire complet** : tous les headers pertinents (max 1024 caractères, troncature automatique)  
- **Validation y/n** avant soumission

### 2. Consultation du statut d'une IP

- **Validation IPv4** stricte (regex 0-255 par octet)  
- **Ouverture automatique** du navigateur sur https://www.abuseipdb.com/check/[IP]

## Prérequis

- PowerShell 5.1+ (Windows 10+ recommandé)  
- Clé API AbuseIPDB (à insérer dans `$API_KEY`)  
  - Récupérable sur : [https://www.abuseipdb.com/account/api](https://www.abuseipdb.com/account/api)

## Limitations de l'API AbuseIPDB

- **Commentaire** : maximum **1024 caractères** (troncature automatique)  
- **Timestamp** : format ISO 8601 requis, maximum 365 jours dans le passé  
- **Rate limiting** : varie selon le niveau de compte (Free/Basic/Premium)

## Analyse intelligente des headers

### Filtrage des "Received: from"

Le script ignore automatiquement les `Received: from` **avant** `Authentication-Results:` (serveurs de réception légitimes).

**Exemple :**
```
Received: from outlook.com [40.107.86.11]  ← IGNORÉ
Authentication-Results: outlook.com; spf=fail...
Received: from evil.com [198.51.100.1]  ← CONSERVÉ (source malveillante)
```

### Analyse contextuelle des IPs différentes

**Si SPF = PASS :**
```
✓ SPF = PASS → Email forwarding légitime ou SMTP relay autorisé
💡 Recommandation : Option 1 (Authentication-Results)
```

**Si SPF = FAIL :**
```
✗ SPF = FAIL → Spoofing / Serveur non autorisé
💡 Recommandation : Option 3 (Received: from)
```

L'utilisateur peut accepter (Entrée) ou choisir manuellement (1/2/3).

## Détection de spoofing

Détection automatique via :
1. **Headers en double** (Authentication-Results, From, Subject, etc.)  
2. **SPF fail** (`spf=pass` absent)  
3. **Domaines différents** (From ≠ Authentication-Results)

→ Catégorie 17 (Spoofing) ajoutée automatiquement si détecté.

## Vérifications implémentées

1. **Normalisation** : fusion des lignes multi-lignes par header  
2. **Validation EML** : présence obligatoire de Authentication-Results, Received-SPF, From  
3. **Détection manipulation** : alerte + sélection manuelle si headers en double  
4. **Extraction IPv4** : regex stricte (0-255 par octet) depuis 3 sources  
5. **Email/Domaine** : regex RFC 5322 (Unicode, caractères spéciaux) + validation domaine (support IDN)  
6. **Analyse SPF** : détection pass/fail → recommandation d'IP contextuelle  
7. **Exclusion mots** : remplacement par "username" dans commentaires  
8. **Timestamp** : parsing depuis Received: from → ISO 8601  
9. **Limitation commentaire** : vérification 1024 chars max, troncature automatique si dépassement  
10. **Gestion erreurs** : capture HTTP détaillée, affichage messages JSON de l'API

## Structure du script

**Fonctions principales :**
- `Normalize-Headers` : fusion des lignes multi-lignes  
- `Extract-Email` : extraction email (regex RFC 5322)  
- `Extract-Domain` : validation domaine (support IDN)  
- `Test-IPv4` : validation IPv4 stricte  
- `Convert-ToISO8601` : conversion date → ISO 8601  
- `Select-FromDuplicates` : sélection manuelle parmi headers en double  
- `Submit-IPFromEML` : fonction principale de soumission  
- `Check-IPStatus` : consultation d'une IP dans le navigateur  

**Workflow :**
1. Lecture + normalisation EML  
2. Extraction + validation headers  
3. Détection doublons → sélection manuelle  
4. Filtrage "Received: from" avant Authentication-Results  
5. Extraction IPs (3 sources)  
6. Analyse SPF → recommandation  
7. Suggestion catégories automatique  
8. Exclusion mots sensibles  
9. Construction commentaire (max 1024 chars)  
10. Extraction timestamp  
11. Récapitulatif + validation y/n  
12. Soumission API + proposition ouverture navigateur

## Usage

### Installation

1. Cloner ce dépôt  
2. Ouvrir `AbuseIPDB_Report.ps1` et définir `$API_KEY`  
3. Lancer :  
```powershell
powershell.exe -ExecutionPolicy Bypass -File .\AbuseIPDB_Report.ps1
```

### Menu principal

```
====================================
  AbuseIPDB - Soumission d'IP
====================================

1. Soumettre une IP malveillante via fichier EML
2. Voir le statut d'une IP
3. Quitter
```

### Option 1 : Soumettre une IP via EML

1. Glisser-déposer le fichier `.eml`  
2. Analyse automatique des headers  
3. Sélection manuelle si headers en double  
4. Recommandation automatique d'IP selon SPF  
5. Validation/modification des catégories  
6. (Optionnel) Exclusion de mots sensibles  
7. Récapitulatif → confirmation y/n  
8. Soumission → proposition ouverture navigateur

### Option 2 : Voir le statut d'une IP

1. Entrer l'IPv4 (ex: `192.168.1.1`)  
2. Ouverture automatique du navigateur

---

**Catégories supportées :**  
- **7** : Phishing  
- **11** : Email Spam  
- **17** : Spoofing

**Suggestion automatique :**  
- `7,11` → Phishing/spam standard  
- `7,11,17` → Phishing/spam avec spoofing détecté

---

Ce script se concentre sur la **soumission précise et contextuelle d'adresses IP malveillantes** issues d'emails de phishing/spam.  
Il utilise uniquement les cmdlets PowerShell natives, sans dépendances tierces.
