# AbuseIPDB_Report.ps1
# Script PowerShell pour soumettre des IP malveillantes à AbuseIPDB
# Auteur: Skip75
# Documentation API : https://docs.abuseipdb.com

# Forcer TLS1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Configuration de l'API
$API_KEY = "VOTRE_CLE_API_ABUSEIPDB"
$API_BASE_URL = "https://api.abuseipdb.com/api/v2"

# ─── Fonction Menu Principal ────────────────────────────────────────────────
function Show-Menu {
    Clear-Host
    Write-Host "====================================" -ForegroundColor Cyan
    Write-Host "  AbuseIPDB - Soumission d'IP" -ForegroundColor Cyan
    Write-Host "====================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Sélectionnez une option:" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "1. Soumettre une IP malveillante via fichier EML" -ForegroundColor Green
    Write-Host "2. Voir le statut d'une IP" -ForegroundColor Green
    Write-Host "3. Quitter" -ForegroundColor Red
    Write-Host ""
    Write-Host -NoNewline "Votre choix (1-3): " -ForegroundColor White
}

# ─── Fonction pour normaliser les headers (supprimer les retours à la ligne) ───
function Normalize-Headers {
    param([string]$Content)

    $lines = $Content -split "`r?`n"
    $normalized = @()
    $currentHeader = ""

    foreach ($line in $lines) {
        if ($line -match "^\s" -and $currentHeader -ne "") {
            $currentHeader += " " + $line.Trim()
        }
        else {
            if ($currentHeader -ne "") {
                $normalized += $currentHeader
            }
            $currentHeader = $line
        }
    }

    if ($currentHeader -ne "") {
        $normalized += $currentHeader
    }

    return $normalized
}

# ─── Fonction pour extraire une adresse email ───────────────────────────────
function Extract-Email {
    param([string]$Text)

    # Regex RFC 5322 complète supportant les emails internationalisés et caractères spéciaux
    $emailPattern = "(?:[\u00A0-\uD7FF\uE000-\uFFFFa-z0-9!#$%&'*+/=?^_``{|}~-]+(?:\.[\u00A0-\uD7FF\uE000-\uFFFFa-z0-9!#$%&'*+/=?^_``{|}~-]+)*|`"(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]|\[\x01-\x09\x0b\x0c\x0e-\x7f])*`")@(?:(?:[\u00A0-\uD7FF\uE000-\uFFFFa-z0-9](?:[\u00A0-\uD7FF\uE000-\uFFFF-a-z0-9-]*[\u00A0-\uD7FF\uE000-\uFFFFa-z0-9])?\.)+[\u00A0-\uD7FF\uE000-\uFFFFa-z0-9](?:[\u00A0-\uD7FF\uE000-\uFFFFa-z0-9-]*[\u00A0-\uD7FF\uE000-\uFFFFa-z0-9])?|\[(?:(?:(2(5[0-5]|[0-4][0-9])|1[0-9][0-9]|[1-9]?[0-9]))\.){3}\])"

    if ($Text -match $emailPattern) {
        return $Matches[0]
    }
    return $null
}

# ─── Fonction pour extraire le domaine d'une adresse email ─────────────────
function Extract-Domain {
    param([string]$Email)

    # Extraire la partie après le @
    if ($Email -match "@(.+)$") {
        $domainPart = $Matches[1]

        # Appliquer la regex complète pour valider et extraire le domaine
        $domainPattern = "((?=[a-z0-9-]{1,63}\.)(xn--)?[a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,63}"
        if ($domainPart -match $domainPattern) {
            return $Matches[0]
        }
    }
    return $null
}

# ─── Fonction pour extraire le domaine depuis Authentication-Results ───────
function Extract-AuthDomain {
    param([string]$AuthHeader)

    $domainPattern = "((?=[a-z0-9-]{1,63}\.)(xn--)?[a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,63}"

    # Chercher dans smtp.mailfrom=
    if ($AuthHeader -match "smtp\.mailfrom=([a-zA-Z0-9.-]+)") {
        $candidate = $Matches[1]
        if ($candidate -match $domainPattern) {
            return $Matches[0]
        }
    }

    # Chercher dans header.from=
    if ($AuthHeader -match "header\.from=([a-zA-Z0-9.-]+)") {
        $candidate = $Matches[1]
        if ($candidate -match $domainPattern) {
            return $Matches[0]
        }
    }

    return $null
}

# ─── Fonction pour valider une IPv4 ─────────────────────────────────────────
function Test-IPv4 {
    param([string]$IP)

    # Regex IPv4 optimisée avec validation stricte (0-255 pour chaque octet)
    $ipPattern = '^(?:(?:\d|[01]?\d\d|2[0-4]\d|25[0-5])\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d|\d)$'
    return $IP -match $ipPattern
}

# ─── Fonction pour ouvrir le navigateur avec l'IP ───────────────────────────
function Open-IPStatus {
    param([string]$IP)

    $url = "https://www.abuseipdb.com/check/$IP"
    Write-Host "`nOuverture du navigateur pour : $url" -ForegroundColor Cyan
    Start-Process $url
    Write-Host "`nAppuyez sur une touche pour revenir au menu..." -ForegroundColor Yellow
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

# ─── Fonction pour convertir la date du header au format ISO 8601 ──────────
function Convert-ToISO8601 {
    param([string]$DateString)

    try {
        $parsedDate = [DateTime]::Parse($DateString)
        return $parsedDate.ToString("yyyy-MM-ddTHH:mm:sszzz")
    }
    catch {
        Write-Host "Erreur lors du parsing de la date: $DateString" -ForegroundColor Red
        return $null
    }
}

# ─── Fonction pour permettre à l'utilisateur de choisir parmi les doublons ───
function Select-FromDuplicates {
    param(
        [string]$HeaderName,
        [array]$Headers
    )

    Write-Host "`nPlusieurs valeurs trouvées pour '$HeaderName' :" -ForegroundColor Yellow
    for ($i = 0; $i -lt $Headers.Count; $i++) {
        $preview = $Headers[$i]
        if ($preview.Length -gt 100) {
            $preview = $preview.Substring(0, 100) + "..."
        }
        Write-Host "  $($i + 1). $preview" -ForegroundColor White
    }

    $choice = Read-Host "`nSélectionnez le numéro à conserver (1-$($Headers.Count))"
    $choiceInt = 0
    while (-not ([int]::TryParse($choice, [ref]$choiceInt) -and $choiceInt -ge 1 -and $choiceInt -le $Headers.Count)) {
        $choice = Read-Host "Saisie invalide. Entrez un numéro entre 1 et $($Headers.Count)"
    }

    return $Headers[$choiceInt - 1]
}

# ─── Fonction Menu 1 : Soumettre IP via fichier EML ─────────────────────────
function Submit-IPFromEML {
    Clear-Host
    Write-Host "Soumission d'IP malveillante via fichier EML" -ForegroundColor Cyan
    Write-Host "=============================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Glissez-déposez le fichier .eml dans cette fenêtre (ou entrez le chemin):" -ForegroundColor Yellow

    $emlPathRaw = Read-Host "Chemin du fichier"
    $emlPathRaw = $emlPathRaw.Trim('"').Trim("'")

    if (-not (Test-Path -LiteralPath $emlPathRaw)) {
        Write-Host "`nErreur : Fichier introuvable : $emlPathRaw" -ForegroundColor Red
        Write-Host "Appuyez sur une touche pour revenir au menu..." -ForegroundColor Yellow
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        return
    }

    # Lecture du fichier
    $emlContent = Get-Content -LiteralPath $emlPathRaw -Raw -Encoding UTF8
    if ([string]::IsNullOrWhiteSpace($emlContent)) {
        Write-Host "`nErreur : Le fichier EML est vide." -ForegroundColor Red
        Write-Host "Appuyez sur une touche pour revenir au menu..." -ForegroundColor Yellow
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        return
    }

    # Normaliser les headers
    Write-Host "`nNormalisation des headers en cours..." -ForegroundColor Cyan
    $normalizedHeaders = Normalize-Headers -Content $emlContent

    # Trouver l'index du premier Authentication-Results
    $authResultsIndex = -1
    for ($i = 0; $i -lt $normalizedHeaders.Count; $i++) {
        if ($normalizedHeaders[$i] -match "^Authentication-Results:") {
            $authResultsIndex = $i
            break
        }
    }

    # Extraction des headers nécessaires
    $authResultsHeaders = $normalizedHeaders | Where-Object { $_ -match "^Authentication-Results:" }
    $receivedSPFHeaders = $normalizedHeaders | Where-Object { $_ -match "^Received-SPF:" }

    # Pour Received: from, ne prendre que ceux APRÈS Authentication-Results
    $receivedFromHeaders = @()
    if ($authResultsIndex -ge 0) {
        for ($i = $authResultsIndex; $i -lt $normalizedHeaders.Count; $i++) {
            if ($normalizedHeaders[$i] -match "^Received: from") {
                $receivedFromHeaders += $normalizedHeaders[$i]
            }
        }
    }

    $receivedByHeaders = $normalizedHeaders | Where-Object { $_ -match "^Received: by" }
    $subjectHeaders = $normalizedHeaders | Where-Object { $_ -match "^Subject:" }
    $fromHeaders = $normalizedHeaders | Where-Object { $_ -match "^From:" }

    # Vérification de la présence des headers
    if ($authResultsHeaders.Count -eq 0 -or $receivedSPFHeaders.Count -eq 0 -or $fromHeaders.Count -eq 0) {
        Write-Host "`nErreur : Le fichier EML ne contient pas les headers nécessaires." -ForegroundColor Red
        Write-Host "Headers manquants :" -ForegroundColor Yellow
        if ($authResultsHeaders.Count -eq 0) { Write-Host "  - Authentication-Results" }
        if ($receivedSPFHeaders.Count -eq 0) { Write-Host "  - Received-SPF" }
        if ($fromHeaders.Count -eq 0) { Write-Host "  - From" }
        Write-Host "`nAppuyez sur une touche pour revenir au menu..." -ForegroundColor Yellow
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        return
    }

    # Gestion des doublons avec sélection utilisateur
    Write-Host "`nVérification de l'unicité des headers..." -ForegroundColor Cyan

    $authResultsHeader = $authResultsHeaders[0]
    if ($authResultsHeaders.Count -gt 1) {
        Write-Host "`nALERTE : Header 'Authentication-Results' trouvé $($authResultsHeaders.Count) fois (possible spoofing) !" -ForegroundColor Red
        $authResultsHeader = Select-FromDuplicates -HeaderName "Authentication-Results" -Headers $authResultsHeaders
    }

    $receivedSPFHeader = $receivedSPFHeaders[0]
    if ($receivedSPFHeaders.Count -gt 1) {
        Write-Host "`nALERTE : Header 'Received-SPF' trouvé $($receivedSPFHeaders.Count) fois (possible spoofing) !" -ForegroundColor Red
        $receivedSPFHeader = Select-FromDuplicates -HeaderName "Received-SPF" -Headers $receivedSPFHeaders
    }

    $fromHeader = $fromHeaders[0]
    if ($fromHeaders.Count -gt 1) {
        Write-Host "`nALERTE : Header 'From' trouvé $($fromHeaders.Count) fois (possible spoofing) !" -ForegroundColor Red
        $fromHeader = Select-FromDuplicates -HeaderName "From" -Headers $fromHeaders
    }

    $subjectHeader = $null
    if ($subjectHeaders.Count -gt 0) {
        $subjectHeader = $subjectHeaders[0]
        if ($subjectHeaders.Count -gt 1) {
            Write-Host "`nALERTE : Header 'Subject' trouvé $($subjectHeaders.Count) fois (possible spoofing) !" -ForegroundColor Red
            $subjectHeader = Select-FromDuplicates -HeaderName "Subject" -Headers $subjectHeaders
        }
    }

    # Pour Received: from après Authentication-Results, permettre à l'utilisateur de choisir s'il y en a plusieurs
    $receivedFromHeader = $null
    if ($receivedFromHeaders.Count -gt 0) {
        if ($receivedFromHeaders.Count -eq 1) {
            $receivedFromHeader = $receivedFromHeaders[0]
            Write-Host "`nInfo : 1 header 'Received: from' trouvé après Authentication-Results." -ForegroundColor Cyan
        }
        else {
            Write-Host "`nInfo : $($receivedFromHeaders.Count) headers 'Received: from' trouvés après Authentication-Results." -ForegroundColor Cyan
            $receivedFromHeader = Select-FromDuplicates -HeaderName "Received: from (après Authentication-Results)" -Headers $receivedFromHeaders
        }
    }

    # Extraction de l'IP depuis Authentication-Results
    $ipFromAuth = $null
    if ($authResultsHeader -match "sender IP is ([0-9.]+)") {
        $ipFromAuth = $Matches[1]
    }

    # Extraction de l'IP depuis Received-SPF
    $ipFromSPF = $null
    if ($receivedSPFHeader -match "client-ip=([0-9.]+)") {
        $ipFromSPF = $Matches[1]
    }

    # Extraction de l'IP depuis Received: from
    $ipFromReceived = $null
    if ($receivedFromHeader -and $receivedFromHeader -match "\[([0-9.]+)\]") {
        $ipFromReceived = $Matches[1]
    }

    # Analyse intelligente de la cohérence des IPs avec contexte SPF
    $finalIP = $null
    $spfPassed = $authResultsHeader -match "spf=pass"
    
    if ($ipFromAuth -eq $ipFromSPF -and $ipFromAuth -eq $ipFromReceived) {
        $finalIP = $ipFromAuth
        Write-Host "`nIP extraite : $finalIP" -ForegroundColor Green
        Write-Host "(Cohérence confirmée dans tous les headers)" -ForegroundColor Cyan
    }
    else {
        Write-Host "`n⚠️ IPs différentes détectées dans les headers" -ForegroundColor Yellow
        Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkGray
        Write-Host "  1. Authentication-Results : $ipFromAuth" -ForegroundColor White
        Write-Host "  2. Received-SPF           : $ipFromSPF" -ForegroundColor White
        Write-Host "  3. Received: from         : $ipFromReceived" -ForegroundColor White
        Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkGray
        
        # Analyse contextuelle et détermination de la recommandation
        Write-Host "`n📊 Analyse contextuelle :" -ForegroundColor Cyan
        
        $recommendedChoice = "1"  # Par défaut Authentication-Results
        
        if ($spfPassed) {
            Write-Host "  ✓ SPF = PASS" -ForegroundColor Green
            Write-Host "    → Cela peut indiquer :" -ForegroundColor Gray
            Write-Host "      • Email forwarding légitime (ex: forwarding automatique)" -ForegroundColor Gray
            Write-Host "      • Service SMTP relay autorisé (ex: Mailchimp, SendGrid)" -ForegroundColor Gray
            Write-Host "      • Load balancer avec plusieurs IPs légitimes" -ForegroundColor Gray
            Write-Host "`n    ⚠️ MAIS si le contenu est malveillant, c'est probablement :" -ForegroundColor Yellow
            Write-Host "      • Un serveur compromis légitime utilisé pour spam" -ForegroundColor Yellow
            Write-Host "      • Une usurpation avec SPF mal configuré" -ForegroundColor Yellow
            $recommendedChoice = "1"
        }
        else {
            Write-Host "  ✗ SPF = FAIL ou SOFTFAIL" -ForegroundColor Red
            Write-Host "    → Cela indique probablement :" -ForegroundColor Gray
            Write-Host "      • Spoofing / Usurpation d'identité" -ForegroundColor Red
            Write-Host "      • Serveur non autorisé pour ce domaine" -ForegroundColor Red
            Write-Host "      • IP source probablement malveillante" -ForegroundColor Red
            $recommendedChoice = "3"
        }
        
        Write-Host "`n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkGray
        Write-Host "`n💡 Recommandation du script :" -ForegroundColor Cyan
        
        if ($recommendedChoice -eq "1") {
            Write-Host "   → Option 1 : Authentication-Results ($ipFromAuth)" -ForegroundColor Green
            Write-Host "     (IP de connexion initiale au serveur de réception)" -ForegroundColor Gray
        }
        else {
            Write-Host "   → Option 3 : Received: from ($ipFromReceived)" -ForegroundColor Green
            Write-Host "     (IP source la plus probable car SPF a échoué)" -ForegroundColor Gray
        }
        
        Write-Host "`n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkGray
        
        $ipChoice = Read-Host "`nQuelle IP souhaitez-vous soumettre ? (1-3) [Entrée = $recommendedChoice recommandé]"
        
        if ([string]::IsNullOrWhiteSpace($ipChoice)) {
            $ipChoice = $recommendedChoice
            Write-Host "Utilisation de la recommandation : option $recommendedChoice" -ForegroundColor Green
        }
        
        switch ($ipChoice) {
            '1' { $finalIP = $ipFromAuth }
            '2' { $finalIP = $ipFromSPF }
            '3' { $finalIP = $ipFromReceived }
            default { 
                Write-Host "`nChoix invalide, utilisation de la recommandation par défaut (option $recommendedChoice)." -ForegroundColor Yellow
                if ($recommendedChoice -eq "1") {
                    $finalIP = $ipFromAuth
                }
                else {
                    $finalIP = $ipFromReceived
                }
            }
        }
    }


    if (-not (Test-IPv4 -IP $finalIP)) {
        Write-Host "`nErreur : L'IP extraite n'est pas valide : '$finalIP'" -ForegroundColor Red
        Write-Host "Format attendu : X.X.X.X (où X = 0-255)" -ForegroundColor Yellow
        Write-Host "`nCauses possibles :" -ForegroundColor Cyan
        Write-Host "  - IP non trouvée dans les headers" -ForegroundColor Gray
        Write-Host "  - Format IPv6 (non supporté actuellement)" -ForegroundColor Gray
        Write-Host "  - Headers malformés" -ForegroundColor Gray
        Write-Host "`nAppuyez sur une touche pour revenir au menu..." -ForegroundColor Yellow
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        return
    }

    # Analyse pour suggestion des catégories
    Write-Host "`nAnalyse des headers pour suggérer les catégories..." -ForegroundColor Cyan

    $suggestedCategories = "7,11"
    $isSpoofing = $false

    # Vérifier SPF
    if ($authResultsHeader -notmatch "spf=pass") {
        $isSpoofing = $true
        Write-Host "  - SPF non passé détecté (spoofing possible)" -ForegroundColor Yellow
    }

    # Vérifier correspondance domaine From vs Authentication-Results
    $emailFrom = Extract-Email -Text $fromHeader
    if ($emailFrom) {
        $domainFrom = Extract-Domain -Email $emailFrom
        $domainAuth = Extract-AuthDomain -AuthHeader $authResultsHeader

        Write-Host "  - Email extrait : $emailFrom" -ForegroundColor Gray
        Write-Host "  - Domaine extrait du From: $domainFrom" -ForegroundColor Gray
        Write-Host "  - Domaine extrait de Authentication-Results: $domainAuth" -ForegroundColor Gray

        if ($domainFrom -and $domainAuth -and $domainFrom -ne $domainAuth) {
            $isSpoofing = $true
            Write-Host "  - Domaine de l'expéditeur ($domainFrom) différent du domaine d'authentification ($domainAuth)" -ForegroundColor Yellow
        }
    }

    if ($isSpoofing) {
        $suggestedCategories = "7,11,17"
    }

    Write-Host "`nCatégories suggérées : $suggestedCategories" -ForegroundColor Cyan
    Write-Host "  7 = Phishing" -ForegroundColor White
    Write-Host "  11 = Email Spam" -ForegroundColor White
    if ($isSpoofing) {
        Write-Host "  17 = Spoofing" -ForegroundColor White
    }

    $categories = Read-Host "`nEntrez les catégories (séparées par des virgules) [Entrée = suggestion]"
    if ([string]::IsNullOrWhiteSpace($categories)) {
        $categories = $suggestedCategories
    }

    # Demander à l'utilisateur d'exclure des mots
    Write-Host "`nSouhaitez-vous exclure des mots sensibles des headers ?" -ForegroundColor Yellow
    $excludeWords = Read-Host "Entrez les mots à exclure (séparés par des virgules) [Entrée = aucun]"

    $wordsToExclude = @()
    if (-not [string]::IsNullOrWhiteSpace($excludeWords)) {
        $wordsToExclude = $excludeWords -split "," | ForEach-Object { $_.Trim() }
    }

    # Construction du commentaire avec tous les headers récupérés
    $commentParts = @()

    if ($authResultsHeader) {
        $cleanHeader = $authResultsHeader
        foreach ($word in $wordsToExclude) {
            if ($word -ne "") {
                $cleanHeader = $cleanHeader -replace [regex]::Escape($word), "username"
            }
        }
        $commentParts += $cleanHeader
    }

    if ($receivedSPFHeader) {
        $cleanHeader = $receivedSPFHeader
        foreach ($word in $wordsToExclude) {
            if ($word -ne "") {
                $cleanHeader = $cleanHeader -replace [regex]::Escape($word), "username"
            }
        }
        $commentParts += $cleanHeader
    }

    if ($receivedFromHeader) {
        $cleanHeader = $receivedFromHeader
        foreach ($word in $wordsToExclude) {
            if ($word -ne "") {
                $cleanHeader = $cleanHeader -replace [regex]::Escape($word), "username"
            }
        }
        $commentParts += $cleanHeader
    }

    if ($subjectHeader) {
        $cleanHeader = $subjectHeader
        foreach ($word in $wordsToExclude) {
            if ($word -ne "") {
                $cleanHeader = $cleanHeader -replace [regex]::Escape($word), "username"
            }
        }
        $commentParts += $cleanHeader
    }

    if ($fromHeader) {
        $cleanHeader = $fromHeader
        foreach ($word in $wordsToExclude) {
            if ($word -ne "") {
                $cleanHeader = $cleanHeader -replace [regex]::Escape($word), "username"
            }
        }
        $commentParts += $cleanHeader
    }

    $comment = $commentParts -join " | "
    
    # Vérifier et tronquer le commentaire si nécessaire (limite API = 1024 caractères)
    if ($comment.Length -gt 1024) {
        Write-Host "`n⚠️ Attention : Le commentaire dépasse 1024 caractères (limite de l'API AbuseIPDB)." -ForegroundColor Yellow
        Write-Host "Il sera tronqué à 1024 caractères pour la soumission." -ForegroundColor Yellow
        $comment = $comment.Substring(0, 1024)
    }
    
    # Extraction de la date depuis Received: from
    $timestamp = $null
    if ($receivedFromHeader -and $receivedFromHeader -match ";\s*(.+)$") {
        $dateString = $Matches[1].Trim()
        $timestamp = Convert-ToISO8601 -DateString $dateString
    }

    # Récapitulatif
    Write-Host "`n=============================================" -ForegroundColor Cyan
    Write-Host "RÉCAPITULATIF DE LA SOUMISSION" -ForegroundColor Cyan
    Write-Host "=============================================" -ForegroundColor Cyan
    Write-Host "IP à soumettre : $finalIP" -ForegroundColor White
    Write-Host "Catégories : $categories" -ForegroundColor White
    if ($timestamp) {
        Write-Host "Timestamp : $timestamp" -ForegroundColor White
    }
    else {
        Write-Host "Timestamp : [heure actuelle sera utilisée]" -ForegroundColor Yellow
    }
    Write-Host "`nCommentaire ($($comment.Length) caractères, max 1024) :" -ForegroundColor White
    if ($comment.Length -gt 500) {
        Write-Host $comment.Substring(0, 500) -ForegroundColor Gray
        Write-Host "... [affichage tronqué pour lisibilité]" -ForegroundColor DarkGray
    }
    else {
        Write-Host $comment -ForegroundColor Gray
    }
    Write-Host "=============================================" -ForegroundColor Cyan

    # Validation
    $confirmation = ""
    while ($confirmation -ne "y" -and $confirmation -ne "n") {
        $confirmation = Read-Host "`nConfirmer la soumission ? (y/n)"
        $confirmation = $confirmation.ToLower().Trim()
    }

    if ($confirmation -eq "n") {
        Write-Host "`nSoumission annulée." -ForegroundColor Yellow
        return
    }

    # Soumission à l'API
    Write-Host "`nSoumission en cours..." -ForegroundColor Cyan

    try {
        $headers = @{
            "Key" = $API_KEY
            "Accept" = "application/json"
        }

        $body = @{
            ip = $finalIP
            categories = $categories
            comment = $comment
        }

        if ($timestamp) {
            $body["timestamp"] = $timestamp
        }

        $response = Invoke-RestMethod -Uri "$API_BASE_URL/report" `
            -Method Post `
            -ContentType "application/x-www-form-urlencoded" `
            -Headers $headers `
            -Body $body `
            -TimeoutSec 10

        Write-Host "`n✓ Soumission réussie !" -ForegroundColor Green
        Write-Host "IP soumise : $($response.data.ipAddress)" -ForegroundColor White
        Write-Host "Score de confiance d'abus : $($response.data.abuseConfidenceScore)%" -ForegroundColor White

        # Proposer d'ouvrir la page de statut
        $openBrowser = Read-Host "`nSouhaitez-vous voir le statut de cette IP dans le navigateur ? (y/n)"
        if ($openBrowser.ToLower() -eq "y") {
            Open-IPStatus -IP $finalIP
        }
        else {
            Write-Host "`nAppuyez sur une touche pour revenir au menu..." -ForegroundColor Yellow
            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        }
    }
    catch {
        $errorMessage = $_.Exception.Message
        $errorResponse = $_.ErrorDetails.Message

        Write-Host "`n✗ Erreur lors de la soumission !" -ForegroundColor Red

        if ($errorResponse) {
            try {
                $errorData = $errorResponse | ConvertFrom-Json
                if ($errorData.errors) {
                    foreach ($error in $errorData.errors) {
                        Write-Host "  $($error.detail)" -ForegroundColor Yellow
                    }
                }
                else {
                    Write-Host $errorResponse -ForegroundColor Yellow
                }
            }
            catch {
                Write-Host $errorResponse -ForegroundColor Yellow
            }
        }
        else {
            Write-Host $errorMessage -ForegroundColor Yellow
        }

        Write-Host "`nAppuyez sur une touche pour revenir au menu..." -ForegroundColor Yellow
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    }
}

# ─── Fonction Menu 2 : Voir le statut d'une IP ──────────────────────────────
function Check-IPStatus {
    Clear-Host
    Write-Host "Vérifier le statut d'une IP" -ForegroundColor Cyan
    Write-Host "============================" -ForegroundColor Cyan
    Write-Host ""

    $ip = Read-Host "Entrez l'adresse IPv4 à vérifier"

    if (-not (Test-IPv4 -IP $ip)) {
        Write-Host "`nErreur : Format d'adresse IPv4 invalide." -ForegroundColor Red
        Write-Host "Exemple de format valide : 192.168.1.1" -ForegroundColor Yellow
        Write-Host "`nAppuyez sur une touche pour revenir au menu..." -ForegroundColor Yellow
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        return
    }

    Open-IPStatus -IP $ip
}

# ─── Boucle principale ───────────────────────────────────────────────────────
do {
    Show-Menu
    $choice = Read-Host

    switch ($choice) {
        '1' { Submit-IPFromEML }
        '2' { Check-IPStatus }
        '3' {
            Write-Host "`nAu revoir !" -ForegroundColor Green
            break
        }
        default {
            Write-Host "`nChoix invalide. Veuillez sélectionner 1, 2 ou 3." -ForegroundColor Red
            Start-Sleep -Seconds 2
        }
    }
} while ($choice -ne '3')
