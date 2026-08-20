<p align="center">
  <img src="assets/banner.png" alt="Anthropic Cybersecurity Skills" width="100%">
</p>

<div align="center">

# Compétences Cybersecurity Anthropic

### La plus grande bibliothèque open source de compétences cybersécurité pour agents IA

[![GARS-2026 Survey](https://img.shields.io/badge/GARS--2026-Take%20the%20Survey-E8B84B?style=for-the-badge&logo=googleforms&logoColor=black)](https://mahipal.engineer/survey?utm_source=github_badge&utm_medium=readme&utm_campaign=gars2026)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg?style=flat-square)](LICENSE)
[![Skills](https://img.shields.io/badge/skills-817-brightgreen?style=flat-square)](#ce-quil-contient-29-domaines-de-securite)
[![Frameworks](https://img.shields.io/badge/frameworks-6-orange?style=flat-square)](#six-frameworks-une-seule-bibliotheque-de-competences)
[![MITRE F3](https://img.shields.io/badge/MITRE-F3_v1.1-blue?style=flat-square)](https://ctid.mitre.org/fraud/)
[![Domains](https://img.shields.io/badge/domains-29-9cf?style=flat-square)](#ce-quil-contient-29-domaines-de-securite)
[![Platforms](https://img.shields.io/badge/platforms-26%2B-blueviolet?style=flat-square)](#plateformes-compatibles)
[![Last Commit](https://img.shields.io/github/last-commit/mukul975/Anthropic-Cybersecurity-Skills?style=flat-square)](https://github.com/mukul975/Anthropic-Cybersecurity-Skills/commits/main)
[![agentskills.io](https://img.shields.io/badge/standard-agentskills.io-ff6600?style=flat-square)](https://agentskills.io)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=flat-square)](CONTRIBUTING.md)
[![Playground](https://img.shields.io/badge/Playground-Casky.ai-blue)](https://casky.ai/?utm_source=github&utm_medium=readme&utm_campaign=cohort_launch#waitlist)
[![Hermes Agent](https://img.shields.io/badge/Hermes_Agent-compatible-blueviolet?style=flat)](https://github.com/NousResearch/hermes-agent)


**817 compétences cybersécurité de niveau production · 29 domaines de sécurité · 6 correspondances de frameworks · 26+ plateformes IA**

[Démarrage rapide](#demarrage-rapide) · [Contenu](#ce-quil-contient-29-domaines-de-securite) · [Frameworks](#six-frameworks-une-seule-bibliotheque-de-competences) · [Plateformes](#plateformes-compatibles) · [Contribuer](#contribuer)

</div>

---

> ⚠️ **Projet communautaire** — Il s'agit d'un projet indépendant créé par la communauté. Non affilié à Anthropic PBC.
>
> 🔐 **Usage autorisé et légal uniquement.** Cette bibliothèque inclut des techniques offensives et à double usage (ex. C2 red-team, simulation de phishing, exploitation) destinées à des **tests d'intrusion autorisés, à la recherche en sécurité, à la défense et à l'éducation**. Ne les utilisez que sur des systèmes que vous possédez ou pour lesquels vous avez une **autorisation écrite explicite** de tester, et respectez toutes les lois applicables ainsi que les règles d'engagement. Vous êtes seul responsable de la façon dont vous utilisez ces compétences. Voir SECURITY.md et CODE_OF_CONDUCT.md.

## Donnez à n'importe quel agent IA les compétences de sécurité d'un analyste senior

Un analyste junior sait quel plugin Volatility3 exécuter sur un dump mémoire suspect, quelles règles Sigma détectent un Kerberoasting, et comment analyser une compromission cloud sur trois fournisseurs. **Votre agent IA ne le sait pas — à moins que vous ne lui fournissiez ces compétences.**

Ce dépôt contient **817 compétences cybersécurité structurées** couvrant **29 domaines de sécurité**, chacune suivant le standard ouvert agentskills.io. Chaque compétence est mappée à **six frameworks de l'industrie** — MITRE ATT&CK, NIST CSF 2.0, MITRE ATLAS, MITRE D3FEND, NIST AI RMF, et le MITRE Fight Fraud Framework (F3) — ce qui en fait la seule bibliothèque open source de compétences offrant une couverture unifiée inter-framework. Clonez-la, pointez votre agent dessus, et votre prochaine investigation sécurité bénéficiera d'un guidage de niveau expert en quelques secondes.

## Six frameworks, une seule bibliothèque de compétences

Aucune autre bibliothèque open source de compétences ne mappe chaque compétence à l'ensemble de ces frameworks. Une compétence, six cases de conformité cochées.

|Framework|Version|Couverture dans ce dépôt|Ce qui est mappé|
|--|--|--|--|
|MITRE ATT&CK|v19.1|15 tactiques · 286 techniques|Comportements adverses et TTP|
|NIST CSF 2.0|2.0|6 fonctions · 22 catégories|Posture de sécurité organisationnelle|
|MITRE ATLAS|v5.4|16 tactiques · 84 techniques|Menaces adverses sur IA/ML|
|MITRE D3FEND|v1.3|7 catégories · 267 techniques|Contre-mesures défensives|
|NIST AI RMF|1.0|4 fonctions · 72 sous-catégories|Gestion des risques IA|
|MITRE F3 (Fight Fraud Framework)|v1.1 (2026-04-09)|8 tactiques · 123 techniques · 94 compétences liées à la fraude|TTP de fraude financière cybernétique|

**Exemple — une seule compétence mappée sur les six frameworks :**

|Compétence|ATT&CK|NIST CSF|ATLAS|D3FEND|AI RMF|F3|
|--|--|--|--|--|--|--|
|`analyzing-network-traffic-of-malware`|T1071|DE.CM|AML.T0047|D3-NTA|MEASURE-2.6|—|
|`detecting-business-email-compromise`|T1566|DE.AE|—|—|—|F1005.006 · monétisation|

### 🆕 MITRE Fight Fraud Framework (F3) — 94 compétences liées à la fraude

Le **MITRE Fight Fraud Framework (F3)** a été publié le **9 avril 2026** par le Center for Threat-Informed Defense (CTID) de MITRE, co-développé avec JPMorganChase, Citigroup, Lloyds Banking Group, Standard Chartered, CrowdStrike, Verizon Business, FS-ISAC, et d'autres. Il s'agit d'un catalogue TTP compatible ATT&CK pour la **fraude financière cybernétique** — comblant le vide laissé par ATT&CK après la compromission initiale.

F3 v1.1 ajoute **deux tactiques spécifiques à la fraude** qu'ATT&CK n'énumère pas :

- **Positioning** (`FA0001`) — actions menées après l'accès pour collecter/manipuler des données et préparer la fraude (ensemencement d'identité synthétique, mise en chauffe de compte, configuration de bénéficiaire, pré-positionnement pour SIM swap, hijack de session bancaire).
- **Monetization** (`FA0002`) — conversion d'actifs volés en fonds utilisables (empilement via money mule, fraude APP, off-ramping crypto, cash-out par carte, abus remboursement/chargeback).

Les techniques spécifiques à la fraude utilisent des IDs `F1XXX` (par ex. `F1005.003` Add Beneficiary, `F1025.003` Wire Transfer, `F1007` Adversary-in-the-Browser) ; les techniques ATT&CK réutilisées conservent leurs IDs `T1XXX`. Les mappings se trouvent dans chaque bloc de frontmatter `mitre_f3:` — les 123 IDs de techniques F3 v1.1 ont tous été vérifiés à partir du bundle STIX upstream. Voir `docs/mitre-f3-mapping.md` pour le schéma.

### MITRE ATT&CK v19.1 — 817/817 compétences mappées

Chaque compétence contient une liste `mitre_attack` en frontmatter validée contre **MITRE ATT&CK v19.1** (la dernière version) à l'aide de la bibliothèque officielle `mitreattack-python` — 286 techniques distinctes sur les 15 tactiques Enterprise, plus des techniques ICS et Mobile lorsque pertinent. Aucun ID révoqué ou obsolète. La restructuration de Defense Evasion dans v19.1 (désormais séparée en **Stealth** et **Defense Impairment**) est reflétée ci-dessous.

|Tactic|ID|Skills|
|--|--|--|
|Reconnaissance|TA0043|103|
|Resource Development|TA0042|22|
|Initial Access|TA0001|467|
|Execution|TA0002|350|
|Persistence|TA0003|444|
|Privilege Escalation|TA0004|464|
|Stealth|TA0005|442|
|Defense Impairment|TA0112|92|
|Credential Access|TA0006|202|
|Discovery|TA0007|237|
|Lateral Movement|TA0008|68|
|Collection|TA0009|172|
|Command and Control|TA0011|123|
|Exfiltration|TA0010|82|
|Impact|TA0040|50|

## Démarrage rapide

```bash
# Option 1 : npx (recommandé)
npx skills add mukul975/Anthropic-Cybersecurity-Skills

# Option 2 : clonage Git
git clone https://github.com/mukul975/Anthropic-Cybersecurity-Skills.git
cd Anthropic-Cybersecurity-Skills
```

Fonctionne immédiatement avec Claude Code, GitHub Copilot, OpenAI Codex CLI, Cursor, Gemini CLI, et toute plateforme compatible agentskills.io.

## 🌍 GARS-2026 — Global Agentic AI Readiness Survey

Je mène une étude académique mondiale mesurant à quel point les professionnels de la sécurité, les développeurs et les équipes d'entreprise sont réellement prêts pour l'IA agentique — serveurs MCP, tool calling, gouvernance, et workflows human-in-the-loop.

**Si vous utilisez ce dépôt, votre réponse serait une donnée réellement précieuse.**

📋 **Répondez à l'enquête (10 min) :** [Survey Link](https://mahipal.engineer/survey?utm_source=github_badge&utm_medium=readme&utm_campaign=gars2026)

- 60 questions · Anonyme · Supervisé par SRH Berlin
- Vous recevez **50 Casky Tokens** pour l'accès anticipé à casky.ai
- Résultats publiés en open access sous CC-BY 4.0

## 🚀 Essayez-le dans le Playground

Découvrez Casky.ai en pratique — aucune configuration requise.

**[→ Lancer le Playground sur Casky.ai](https://casky.ai/?utm_source=github&utm_medium=readme&utm_campaign=cohort_launch#waitlist)**

Le playground vous permet de :

- Exécuter des exercices de compétences cybersécurité en direct sur de vraies cibles
- Voir des agents IA exécuter des compétences structurées en temps réel
- Explorer de manière interactive des workflows mappés à MITRE ATT&CK
- Tester des scénarios de threat hunting, DFIR et pentest

Pas d'installation. Pas de configuration. Juste ouvrir et commencer.

## Pourquoi ce projet existe

La pénurie de main-d'œuvre en cybersécurité a atteint **4,8 millions de postes non pourvus** dans le monde en 2024 (ISC2). Les agents IA peuvent aider à combler cet écart — mais seulement s'ils disposent d'une base de connaissances métier structurée.

Les agents actuels savent écrire du code et chercher sur le web, mais ils n'ont pas les playbooks praticiens qui transforment un LLM générique en analyste sécurité compétent.

Les dépôts d'outils de sécurité existants fournissent des wordlists, des payloads ou du code d'exploitation. Aucun ne fournit à un agent IA le workflow de décision structuré qu'un analyste senior suit : quand utiliser chaque technique, quelles préconditions vérifier, comment exécuter étape par étape, et comment valider les résultats. C'est cet écart que ce projet comble.

**Anthropic Cybersecurity Skills** n'est pas une collection de scripts ou de checklists. C'est une **base de connaissances native IA** conçue dès l'origine pour le standard agentskills.io — frontmatter YAML pour la découverte en sous-seconde, Markdown structuré pour l'exécution pas à pas, et fichiers de référence pour le contexte technique approfondi. Chaque compétence encode de vrais workflows praticiens, pas des résumés générés.

## Ce qu'il contient — 29 domaines de sécurité

|Domaine|Compétences|Capacités clés|
|--|--|--|
|Cloud Security|66|AWS, Azure, GCP hardening · CSPM · émulation d'attaques cloud · forensics cloud|
|Threat Hunting|58|Chasse guidée par hypothèses · détection LOTL · chasse EVTX · chasse à l'échelle du parc|
|Threat Intelligence|52|STIX/TAXII · MISP · OpenCTI · intégration de flux · profilage d'acteurs|
|Network Security|43|IDS/IPS · règles de pare-feu · segmentation VLAN · analyse du trafic|
|Web Application Security|42|OWASP Top 10 · SQLi · XSS · SSRF · désérialisation|
|Digital Forensics|41|Imagerie disque · forensique mémoire · chronologies Hayabusa/KAPE/Plaso|
|Malware Analysis|39|Analyse statique/dynamique · rétro-ingénierie · sandboxing|
|Identity & Access Management|37|Entra ID/ROADtools · phishing par code d'appareil · PAM · identité zero trust|
|SOC Operations|35|Playbooks · workflows d'escalade · détection Graph-log · exercices tabletop|
|Red Teaming|33|ADCS/Certipy · BloodHound CE · C2 Sliver/Havoc · relais NTLM|
|Container Security|33|RBAC Kubernetes · scan d'images · Falco · évasion de conteneurs|
|Security Operations|28|Corrélation SIEM · analyse de logs · triage d'alertes|
|OT/ICS Security|28|Modbus · DNP3 · IEC 62443 · défense des historian · SCADA|
|API Security|28|GraphQL · REST · OWASP API Top 10 · contournement WAF|
|Incident Response|26|Confinement de compromission · réponse ransomware · playbooks IR|
|Vulnerability Management|25|Nessus · workflows de scan · priorisation des patchs · CVSS|
|Penetration Testing|21|Réseau · web · cloud · mobile · mouvement latéral NetExec|
|DevSecOps|18|Sécurité CI/CD · scan Trivy IaC/images · signature de code|
|Zero Trust Architecture|17|BeyondCorp · modèle de maturité CISA · microsegmentation|
|Endpoint Security|17|EDR · détection LOTL · malware fileless · chasse à la persistance|
|Cryptography|16|TLS · Ed25519 · migration post-quantique · gestion des clés|
|Phishing Defense|15|Authentification email · détection BEC · IR phishing|
|AI Security|14|Red-teaming LLM (garak/PyRIT) · injection de prompt · sécurité MCP/agentique · garde-fous|
|Mobile Security|13|Analyse Android/iOS · pentest mobile · forensics MDM|
|Ransomware Defense|13|Détection précurseur · réponse · récupération · analyse du chiffrement|
|Compliance & Governance|9|NIST 800-30/RMF · CMMC · HIPAA · TPRM · CIS benchmarks|
|Supply Chain Security|8|SBOMs · confusion de dépendances · triage de paquets malveillants · SLSA/Sigstore|
|Deception Technology|6|Honeytokens · canarytokens · détection de compromission|
|Hardware & Firmware Security|4|Audit CHIPSEC/UEFI · contournement Secure Boot · attestation TPM · chasse aux bootkits|

## Comment les agents IA utilisent ces compétences

Chaque compétence coûte **environ 30 tokens à scanner** (seulement le frontmatter) et **500 à 2 000 tokens à charger entièrement** (workflow complet). Cette architecture de divulgation progressive permet aux agents de parcourir les 817 compétences en une seule passe sans exploser les fenêtres de contexte.

```text
Prompt utilisateur : "Analyse ce dump mémoire pour des signes de vol d'identifiants"

Processus interne de l'agent :

  1. Scanne les frontmatters des 817 compétences (~30 tokens chacun)
     → identifie 12 compétences pertinentes en faisant correspondre tags, description, domaine

  2. Charge les 3 meilleurs résultats :
     -  performing-memory-forensics-with-volatility3
     -  hunting-for-credential-dumping-lsass
     -  analyzing-windows-event-logs-for-credential-access

  3. Exécute le workflow structuré étape par étape
     → lance les plugins Volatility3, vérifie les schémas d'accès à LSASS,
        corrèle avec les preuves des journaux d'événements

  4. Valide les résultats à l'aide de la section Verification
     → confirme les IOCs, mappe les constatations vers ATT&CK T1003 (Credential Dumping)
```

**Sans ces compétences**, l'agent devine les commandes d'outils et rate des étapes critiques. **Avec elles**, il suit le même playbook qu'un analyste DFIR senior.

## Anatomie d'une compétence

Chaque compétence suit une structure de répertoire cohérente :

```text
skills/performing-memory-forensics-with-volatility3/
├── SKILL.md ← Définition de la compétence (frontmatter YAML + corps Markdown)
├── references/
│ ├── standards.md ← Mappages MITRE ATT&CK, ATLAS, D3FEND, NIST
│ └── workflows.md ← Référence détaillée de procédure technique
├── scripts/
│ └── process.py ← Scripts d'assistance opérationnels
└── assets/
    └── template.md ← Checklists et modèles de rapport remplis
```

### Frontmatter YAML (exemple réel)

```yaml
---
name: performing-memory-forensics-with-volatility3
description: >-
  Analyser des dumps mémoire pour extraire les processus en cours,
  les connexions réseau, le code injecté et les artefacts malware à l'aide
  du framework Volatility3.
domain: cybersecurity
subdomain: digital-forensics
tags: [forensics, memory-analysis, volatility3, incident-response, dfir]
atlas_techniques: [AML.T0047]
d3fend_techniques: [D3-MA, D3-PSMD]
nist_ai_rmf: [MEASURE-2.6]
nist_csf: [DE.CM-01, RS.AN-03]
version: "1.2"
author: mukul975
license: Apache-2.0
---
```

### Sections du corps Markdown

```md
## When to Use
Conditions de déclenchement — quand un agent IA doit-il activer cette compétence ?

## Prerequisites
Outils requis, niveaux d'accès et configuration d'environnement.

## Workflow
Guide d'exécution pas à pas avec commandes spécifiques et points de décision.

## Verification
Comment confirmer que la compétence a été exécutée avec succès.
```

Les champs du frontmatter : `name` (kebab-case, 1–64 caractères), `description` (riche en mots-clés pour la découverte par agent), `domain`, `subdomain`, `tags`, `atlas_techniques` (IDs MITRE ATLAS), `d3fend_techniques` (IDs MITRE D3FEND), `nist_ai_rmf` (références NIST AI RMF), `nist_csf` (catégories NIST CSF 2.0). Les mappages MITRE ATT&CK sont documentés dans le fichier `references/standards.md` de chaque compétence et dans la couche ATT&CK Navigator incluse dans les releases.

**📊 Couverture MITRE ATT&CK Enterprise — les 15 tactiques**

|Tactic|ID|Coverage|Key skills|
|--|--|--|--|
|Reconnaissance|TA0043|Strong|OSINT, énumération de sous-domaines, reconnaissance DNS|
|Resource Development|TA0042|Moderate|Infrastructure de phishing, détection de mise en place C2|
|Initial Access|TA0001|Strong|Simulation de phishing, détection d'exploit, forced browsing|
|Execution|TA0002|Strong|Analyse PowerShell, malware fileless, script block logging|
|Persistence|TA0003|Strong|Tâches planifiées, registre, comptes de service, LOTL|
|Privilege Escalation|TA0004|Strong|Kerberoasting, attaques AD, élévation de privilèges cloud|
|Stealth|TA0005|Strong|Obfuscation, analyse rootkit, détection d'évasion|
|Defense Impairment|TA0112|Strong|Désactivation EDR, destruction de logs, contournement de défenses|
|Credential Access|TA0006|Strong|Détection Mimikatz, pass-the-hash, credential dumping|
|Discovery|TA0007|Moderate|BloodHound, énumération AD, scan réseau|
|Lateral Movement|TA0008|Strong|Exploits SMB, détection des déplacements latéraux avec Splunk|
|Collection|TA0009|Moderate|Forensics email, détection de data staging|
|Command and Control|TA0011|Strong|Beaconing C2, DNS tunneling, analyse Cobalt Strike|
|Exfiltration|TA0010|Strong|Exfiltration DNS, contrôles DLP, détection de perte de données|
|Impact|TA0040|Strong|Défense ransomware, analyse du chiffrement, récupération|

Un fichier de couche **ATT&CK Navigator** est inclus dans les assets de release v1.0.0 pour la visualisation de la couverture.

**📊 Alignement NIST CSF 2.0 — les 6 fonctions**

|Function|Skills|Examples|
|--|--|--|
|**Govern (GV)**|30+|Stratégie de risque, cadres de politique, rôles et responsabilités|
|**Identify (ID)**|120+|Découverte des actifs, évaluation du paysage de menaces, analyse du risque|
|**Protect (PR)**|150+|Durcissement IAM, règles WAF, zero trust, chiffrement|
|**Detect (DE)**|200+|Threat hunting, corrélation SIEM, détection d'anomalies|
|**Respond (RS)**|160+|Réponse à incident, forensics, confinement d'une compromission|
|**Recover (RC)**|40+|Récupération ransomware, BCP, reprise après sinistre|

NIST CSF 2.0 (février 2024) a ajouté la fonction **Govern** et étendu le périmètre des infrastructures critiques à toutes les organisations. Les mappages des compétences s'alignent sur les 22 catégories et font référence à 106 sous-catégories.

**📊 Analyse approfondie des frameworks — ATLAS, D3FEND, AI RMF**

### MITRE ATLAS v5.4 — Menaces adverses IA/ML

ATLAS mappe les tactiques, techniques et cas d'usage adverses spécifiques aux systèmes d'IA et de machine learning. La version 5.4 couvre **16 tactiques et 84 techniques**, y compris les vecteurs d'attaque agentiques ajoutés fin 2025 : empoisonnement du contexte d'un agent IA, abus d'invocation d'outils, compromission de serveurs MCP, et déploiement d'agents malveillants. Les compétences mappées à ATLAS aident les agents à identifier et contrer les menaces visant les pipelines ML, les poids de modèles, les API d'inférence et les workflows autonomes.

### MITRE D3FEND v1.3 — Contre-mesures défensives

D3FEND est un graphe de connaissances financé par la NSA contenant **267 techniques défensives** organisées en 7 catégories tactiques : Model, Harden, Detect, Isolate, Deceive, Evict et Restore. Construit sur l'ontologie OWL 2, il utilise une couche Digital Artifact partagée pour mapper bidirectionnellement les contre-mesures défensives aux techniques offensives ATT&CK. Les compétences taguées avec des identifiants D3FEND permettent aux agents de recommander des contre-mesures précises pour les menaces détectées.

### NIST AI RMF 1.0 + GenAI Profile (AI 600-1)

Le cadre AI Risk Management Framework définit 4 fonctions centrales — Govern, Map, Measure, Manage — avec **72 sous-catégories** pour un développement IA digne de confiance. Le GenAI Profile (AI 600-1, juillet 2024) ajoute **12 catégories de risque** spécifiques à l'IA générative, de la confabulation et de la confidentialité des données à l'injection de prompt et aux risques de chaîne d'approvisionnement. Le Colorado AI Act (entré en vigueur en février 2026) offre un **safe harbor légal** aux organisations conformes au NIST AI RMF, rendant ces mappages directement pertinents pour la conformité réglementaire.

## Plateformes compatibles

**Assistants de code IA**
Claude Code (Anthropic) · GitHub Copilot (Microsoft) · Cursor · Windsurf · Cline · Aider · Continue · Roo Code · Amazon Q Developer · Tabnine · Sourcegraph Cody · JetBrains AI

**Agents CLI**
OpenAI Codex CLI · Gemini CLI (Google)

**Agents autonomes**
Devin · Replit Agent · SWE-agent · OpenHands

**Frameworks & SDKs d'agents**
LangChain · CrewAI · AutoGen · Semantic Kernel · Haystack · Vercel AI SDK · Tout agent compatible MCP

Toutes les plateformes supportant le standard agentskills.io peuvent charger ces compétences sans configuration.

## Ce qu'ils en disent

> _"Une base de données de vraies compétences de sécurité organisées que n'importe quel agent IA peut brancher et utiliser. Pas des tutoriels. Pas des articles de blog."_
> — **Hasan Toor (@hasantoxr)**, créateur IA/tech

> _"Ce n'est pas une collection aléatoire de scripts de sécurité. C'est une base de connaissances opérationnelle structurée conçue pour les workflows de sécurité pilotés par IA."_
> — **fazal-sec**, Medium

## Mentionné dans

| Où | Type | Lien |
|--|--|--|
| **awesome-agent-skills** | Awesome List (index de 1000+ compétences) | VoltAgent/awesome-agent-skills |
| **awesome-ai-security** | Awesome List (outils de sécurité IA) | ottosulin/awesome-ai-security |
| **awesome-codex-cli** | Awesome List (ressources Codex CLI) | RoggeOhta/awesome-codex-cli |
| **SkillsLLM** | Annuaire & marketplace de compétences | skillsllm.com/skill/anthropic-cybersecurity-skills |
| **Openflows** | Analyse & suivi de signaux | openflows.org |
| **NeverSight skills_feed** | Index automatisé des compétences | NeverSight/skills_feed |

## Historique des étoiles

![Star History Chart](https://star-history.dera.page/svg?repos=mukul975/Anthropic-Cybersecurity-Skills&type=Date)

## Releases

| Version | Date | Points forts |
|--|--|--|
| v1.0.0 | 11 mars 2026 | 734 compétences · 26 domaines · Mappage MITRE ATT&CK + NIST CSF 2.0 · Couche ATT&CK Navigator |

Les compétences continuent de croître sur `main` depuis la v1.0.0 — la bibliothèque contient désormais **817 compétences** avec un **mappage sur 6 frameworks** (MITRE ATLAS, D3FEND, NIST AI RMF, et le MITRE Fight Fraud Framework ajoutés après la release). Consultez les Releases pour la dernière version taguée.

## Contribuer

Ce projet évolue grâce aux contributions de la communauté. Voici comment participer :

**Ajouter une nouvelle compétence** — Les domaines comme Deception Technology (6 compétences) et Hardware & Firmware Security (4 compétences) ont le plus besoin d'aide. Suivez le modèle dans CONTRIBUTING.md et soumettez une PR avec le titre `Add skill: nom-de-votre-competence`.

**Améliorer les compétences existantes** — Ajoutez des mappages de frameworks, corrigez les workflows, mettez à jour les références d'outils, ou contribuez avec des scripts et modèles.

**Signaler des problèmes** — Vous avez trouvé une procédure inexacte ou un script cassé ? Ouvrez une issue.

Chaque PR est revue pour sa précision technique et sa conformité au standard agentskills.io dans les 48 heures. Consultez les *good first issues* pour commencer.

Ce projet suit le Contributor Covenant. En participant, vous acceptez de respecter ce code.

## Communauté

💬 **Discussions** — Questions, idées et conversations sur la feuille de route
🐛 **Issues** — Rapports de bugs et demandes de fonctionnalités
🔒 **Politique de sécurité** — Processus de divulgation responsable (accusé de réception sous 48h)

## Citation

Si vous utilisez ce projet dans des recherches ou publications :

```bibtex
@software{anthropic_cybersecurity_skills,
  author       = {Jangra, Mahipal},
  title        = {Anthropic Cybersecurity Skills},
  year         = {2026},
  url          = {https://github.com/mukul975/Anthropic-Cybersecurity-Skills},
  license      = {Apache-2.0},
  note         = {817 compétences cybersécurité structurées pour agents IA,
                  mappées à MITRE ATT\&CK, NIST CSF 2.0, MITRE ATLAS,
                  MITRE D3FEND et NIST AI RMF}
}
```

## Licence

Ce projet est sous licence Apache License 2.0. Vous êtes libre d'utiliser, modifier et distribuer ces compétences dans des projets personnels comme commerciaux.

---

<div align="center">

**Si ce projet aide votre travail en sécurité, pensez à lui donner une ⭐**

> [⭐ Star](https://github.com/mukul975/Anthropic-Cybersecurity-Skills/stargazers) · [🍴 Fork](https://github.com/mukul975/Anthropic-Cybersecurity-Skills/fork) · [💬 Discuss](https://github.com/mukul975/Anthropic-Cybersecurity-Skills/discussions) · [📝 Contribute](CONTRIBUTING.md~~~

*Projet communautaire par @mukul975. Non affilié à Anthropic PBC.*

</div>
