<#
.SYNOPSIS
    Auditoria de Política de Senha Local do Windows

.DESCRIPTION
    Este script coleta e exibe as configurações de política de senha locais
    do Windows, incluindo comprimento mínimo, complexidade, histórico de senhas
    e validade máxima. Requer privilégios administrativos.

.NOTES
    Autor: AndersonC75
    Data: 29/09/2025
    Versão: 1.0
    Requisitos: Windows PowerShell 5.1+ ou PowerShell Core 7+
                Privilégios de Administrador

.EXAMPLE
    .\Audit-PasswordPolicy.ps1
    Executa a auditoria e exibe as configurações de política de senha
#>

# Verifica se o script está sendo executado com privilégios de administrador
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Warning "Este script requer privilégios de administrador. Execute o PowerShell como Administrador."
    exit 1
}

# Função para obter políticas de senha usando net accounts
function Get-LocalPasswordPolicy {
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "  AUDITORIA DE POLÍTICA DE SENHA LOCAL" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    
    try {
        # Executa o comando net accounts e captura a saída
        $netAccountsOutput = net accounts
        
        # Inicializa um objeto para armazenar as configurações
        $passwordPolicy = [PSCustomObject]@{
            'ComprimentoMinimoSenha' = ''
            'ValidadeMaximaSenha' = ''
            'ValidadeMinimaSenha' = ''
            'HistoricoSenhas' = ''
            'BloqueioAposTentativas' = ''
            'DuracaoBloqueio' = ''
            'ResetarContadorBloqueio' = ''
        }
        
        # Processa cada linha da saída
        foreach ($line in $netAccountsOutput) {
            if ($line -match 'Minimum password length|Comprimento mínimo da senha') {
                $passwordPolicy.ComprimentoMinimoSenha = ($line -split ':')[1].Trim()
            }
            elseif ($line -match 'Maximum password age|Validade máxima da senha') {
                $passwordPolicy.ValidadeMaximaSenha = ($line -split ':')[1].Trim()
            }
            elseif ($line -match 'Minimum password age|Validade mínima da senha') {
                $passwordPolicy.ValidadeMinimaSenha = ($line -split ':')[1].Trim()
            }
            elseif ($line -match 'Length of password history|Comprimento do histórico de senhas') {
                $passwordPolicy.HistoricoSenhas = ($line -split ':')[1].Trim()
            }
            elseif ($line -match 'Lockout threshold|Limite de bloqueio') {
                $passwordPolicy.BloqueioAposTentativas = ($line -split ':')[1].Trim()
            }
            elseif ($line -match 'Lockout duration|Duração do bloqueio') {
                $passwordPolicy.DuracaoBloqueio = ($line -split ':')[1].Trim()
            }
            elseif ($line -match 'Lockout observation window|Janela de observação de bloqueio') {
                $passwordPolicy.ResetarContadorBloqueio = ($line -split ':')[1].Trim()
            }
        }
        
        # Exibe as configurações
        Write-Host "Comprimento Mínimo da Senha:      $($passwordPolicy.ComprimentoMinimoSenha)" -ForegroundColor Green
        Write-Host "Validade Máxima da Senha:         $($passwordPolicy.ValidadeMaximaSenha)" -ForegroundColor Green
        Write-Host "Validade Mínima da Senha:         $($passwordPolicy.ValidadeMinimaSenha)" -ForegroundColor Green
        Write-Host "Histórico de Senhas Mantido:      $($passwordPolicy.HistoricoSenhas)" -ForegroundColor Green
        Write-Host "Bloqueio Após Tentativas:         $($passwordPolicy.BloqueioAposTentativas)" -ForegroundColor Green
        Write-Host "Duração do Bloqueio:              $($passwordPolicy.DuracaoBloqueio)" -ForegroundColor Green
        Write-Host "Resetar Contador de Bloqueio:     $($passwordPolicy.ResetarContadorBloqueio)" -ForegroundColor Green
        
        Write-Host ""
        
        # Verifica requisitos de complexidade através de secedit
        Write-Host "Verificando requisitos de complexidade de senha..." -ForegroundColor Yellow
        
        $tempFile = [System.IO.Path]::GetTempFileName()
        secedit /export /cfg $tempFile /quiet
        
        $complexityEnabled = Select-String -Path $tempFile -Pattern "PasswordComplexity" | ForEach-Object {
            if ($_ -match "PasswordComplexity\s*=\s*1") {
                "Habilitada"
            } else {
                "Desabilitada"
            }
        }
        
        Write-Host "Complexidade de Senha:            $complexityEnabled" -ForegroundColor Green
        
        # Remove arquivo temporário
        Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
        
        Write-Host ""
        Write-Host "========================================" -ForegroundColor Cyan
        Write-Host "  ANÁLISE DE CONFORMIDADE" -ForegroundColor Cyan
        Write-Host "========================================" -ForegroundColor Cyan
        Write-Host ""
        
        # Análise de conformidade baseada em boas práticas
        $warnings = @()
        
        # Verifica comprimento mínimo (recomendado: 12 ou mais)
        $minLength = [int]($passwordPolicy.ComprimentoMinimoSenha -replace '[^0-9]','')
        if ($minLength -lt 12) {
            $warnings += "⚠ Comprimento mínimo de senha abaixo do recomendado (recomendado: 12+)"
        }
        
        # Verifica histórico de senhas (recomendado: 24 ou mais)
        $historyLength = [int]($passwordPolicy.HistoricoSenhas -replace '[^0-9]','')
        if ($historyLength -lt 24) {
            $warnings += "⚠ Histórico de senhas abaixo do recomendado (recomendado: 24+)"
        }
        
        # Verifica se complexidade está habilitada
        if ($complexityEnabled -eq "Desabilitada") {
            $warnings += "⚠ Complexidade de senha não está habilitada (recomendado: Habilitada)"
        }
        
        # Verifica bloqueio de conta
        $lockoutThreshold = [int]($passwordPolicy.BloqueioAposTentativas -replace '[^0-9]','')
        if ($lockoutThreshold -eq 0 -or $lockoutThreshold -gt 10) {
            $warnings += "⚠ Limite de bloqueio não configurado adequadamente (recomendado: 5-10 tentativas)"
        }
        
        if ($warnings.Count -eq 0) {
            Write-Host "✓ Todas as políticas de senha estão em conformidade com as boas práticas!" -ForegroundColor Green
        } else {
            Write-Host "Avisos encontrados:" -ForegroundColor Yellow
            foreach ($warning in $warnings) {
                Write-Host $warning -ForegroundColor Yellow
            }
        }
        
        Write-Host ""
        Write-Host "Auditoria concluída em: $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')" -ForegroundColor Cyan
        
        return $passwordPolicy
        
    } catch {
        Write-Error "Erro ao obter políticas de senha: $_"
        return $null
    }
}

# Executa a função principal
Get-LocalPasswordPolicy
