<#
.SYNOPSIS
    Auditoria de Configuração do Windows Firewall

.DESCRIPTION
    Este script coleta e exibe informações detalhadas sobre as configurações do Windows Firewall,
    incluindo perfis ativos, regras habilitadas e status de cada perfil (Domínio, Privado e Público).

.NOTES
    Nome do Arquivo: Audit-FirewallConfig.ps1
    Autor: PowerShell Security Audit Team
    Requerimentos: PowerShell 5.1 ou superior, privilégios administrativos
    Data: 29/09/2025

.EXAMPLE
    .\Audit-FirewallConfig.ps1
    Executa a auditoria completa do Windows Firewall
#>

# Requer privilégios administrativos para executar
#Requires -RunAsAdministrator

# Limpa a tela para melhor visualização
Clear-Host

Write-Host "===============================================" -ForegroundColor Cyan
Write-Host "   AUDITORIA DE CONFIGURAÇÃO DO FIREWALL      " -ForegroundColor Cyan
Write-Host "===============================================" -ForegroundColor Cyan
Write-Host ""

# ====================================================================
# SEÇÃO 1: Coleta informações sobre os perfis do Firewall
# ====================================================================

Write-Host "[1] PERFIS DO WINDOWS FIREWALL" -ForegroundColor Yellow
Write-Host "-------------------------------------------" -ForegroundColor Yellow
Write-Host ""

try {
    # Obtém informações de todos os perfis do firewall (Domínio, Privado, Público)
    $FirewallProfiles = Get-NetFirewallProfile
    
    foreach ($Profile in $FirewallProfiles) {
        Write-Host "Perfil: $($Profile.Name)" -ForegroundColor Green
        Write-Host "  Status: $($Profile.Enabled)" -ForegroundColor White
        Write-Host "  Bloqueio Padrão (Entrada): $($Profile.DefaultInboundAction)" -ForegroundColor White
        Write-Host "  Bloqueio Padrão (Saída): $($Profile.DefaultOutboundAction)" -ForegroundColor White
        Write-Host "  Permitir Notificações: $($Profile.NotifyOnListen)" -ForegroundColor White
        Write-Host "  Log Permitido: $($Profile.LogAllowed)" -ForegroundColor White
        Write-Host "  Log Bloqueado: $($Profile.LogBlocked)" -ForegroundColor White
        Write-Host "  Caminho do Log: $($Profile.LogFileName)" -ForegroundColor White
        Write-Host "  Tamanho Máx. Log: $($Profile.LogMaxSizeKilobytes) KB" -ForegroundColor White
        Write-Host ""
    }
}
catch {
    Write-Host "ERRO ao obter perfis do firewall: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host ""
}

# ====================================================================
# SEÇÃO 2: Identifica o perfil ativo no momento
# ====================================================================

Write-Host "[2] PERFIL ATIVO ATUAL" -ForegroundColor Yellow
Write-Host "-------------------------------------------" -ForegroundColor Yellow
Write-Host ""

try {
    # Verifica qual perfil está ativo baseado nas conexões de rede atuais
    $ActiveProfile = Get-NetConnectionProfile | Select-Object Name, NetworkCategory, InterfaceAlias
    
    foreach ($Connection in $ActiveProfile) {
        Write-Host "Interface: $($Connection.InterfaceAlias)" -ForegroundColor Green
        Write-Host "  Nome da Rede: $($Connection.Name)" -ForegroundColor White
        Write-Host "  Categoria: $($Connection.NetworkCategory)" -ForegroundColor White
        Write-Host ""
    }
}
catch {
    Write-Host "ERRO ao obter perfil ativo: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host ""
}

# ====================================================================
# SEÇÃO 3: Lista regras do Firewall habilitadas
# ====================================================================

Write-Host "[3] REGRAS DO FIREWALL HABILITADAS" -ForegroundColor Yellow
Write-Host "-------------------------------------------" -ForegroundColor Yellow
Write-Host ""

try {
    # Obtém todas as regras habilitadas do firewall
    $EnabledRules = Get-NetFirewallRule | Where-Object { $_.Enabled -eq $true }
    
    Write-Host "Total de regras habilitadas: $($EnabledRules.Count)" -ForegroundColor Cyan
    Write-Host ""
    
    # Agrupa por direção (Entrada/Saída) e ação (Permitir/Bloquear)
    $InboundAllow = ($EnabledRules | Where-Object { $_.Direction -eq 'Inbound' -and $_.Action -eq 'Allow' }).Count
    $InboundBlock = ($EnabledRules | Where-Object { $_.Direction -eq 'Inbound' -and $_.Action -eq 'Block' }).Count
    $OutboundAllow = ($EnabledRules | Where-Object { $_.Direction -eq 'Outbound' -and $_.Action -eq 'Allow' }).Count
    $OutboundBlock = ($EnabledRules | Where-Object { $_.Direction -eq 'Outbound' -and $_.Action -eq 'Block' }).Count
    
    Write-Host "Regras de ENTRADA:" -ForegroundColor Green
    Write-Host "  Permitir: $InboundAllow" -ForegroundColor White
    Write-Host "  Bloquear: $InboundBlock" -ForegroundColor White
    Write-Host ""
    
    Write-Host "Regras de SAÍDA:" -ForegroundColor Green
    Write-Host "  Permitir: $OutboundAllow" -ForegroundColor White
    Write-Host "  Bloquear: $OutboundBlock" -ForegroundColor White
    Write-Host ""
    
    # Lista as primeiras 10 regras de entrada habilitadas como exemplo
    Write-Host "Exemplos de Regras de Entrada Habilitadas (Top 10):" -ForegroundColor Cyan
    $EnabledRules | Where-Object { $_.Direction -eq 'Inbound' } | Select-Object -First 10 | ForEach-Object {
        Write-Host "  - $($_.DisplayName) [$($_.Action)]" -ForegroundColor White
    }
    Write-Host ""
    
}
catch {
    Write-Host "ERRO ao obter regras do firewall: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host ""
}

# ====================================================================
# SEÇÃO 4: Verifica status do serviço de Firewall
# ====================================================================

Write-Host "[4] STATUS DO SERVIÇO DE FIREWALL" -ForegroundColor Yellow
Write-Host "-------------------------------------------" -ForegroundColor Yellow
Write-Host ""

try {
    # Verifica o status do serviço Windows Firewall (mpssvc)
    $FirewallService = Get-Service -Name mpssvc
    
    Write-Host "Nome do Serviço: $($FirewallService.DisplayName)" -ForegroundColor Green
    Write-Host "  Status: $($FirewallService.Status)" -ForegroundColor White
    Write-Host "  Tipo de Inicialização: $($FirewallService.StartType)" -ForegroundColor White
    Write-Host ""
    
    # Alerta se o serviço não estiver em execução
    if ($FirewallService.Status -ne 'Running') {
        Write-Host "ALERTA: O serviço de Firewall não está em execução!" -ForegroundColor Red
        Write-Host ""
    }
}
catch {
    Write-Host "ERRO ao verificar serviço do firewall: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host ""
}

# ====================================================================
# SEÇÃO 5: Resumo de Segurança
# ====================================================================

Write-Host "[5] RESUMO DE SEGURANÇA" -ForegroundColor Yellow
Write-Host "-------------------------------------------" -ForegroundColor Yellow
Write-Host ""

try {
    # Verifica se todos os perfis estão habilitados
    $DisabledProfiles = $FirewallProfiles | Where-Object { $_.Enabled -eq $false }
    
    if ($DisabledProfiles.Count -eq 0) {
        Write-Host "✓ Todos os perfis do firewall estão habilitados" -ForegroundColor Green
    } else {
        Write-Host "✗ ALERTA: Os seguintes perfis estão desabilitados:" -ForegroundColor Red
        foreach ($Profile in $DisabledProfiles) {
            Write-Host "  - $($Profile.Name)" -ForegroundColor Red
        }
    }
    Write-Host ""
    
    # Verifica configurações padrão de bloqueio
    $WeakProfiles = $FirewallProfiles | Where-Object { 
        $_.DefaultInboundAction -ne 'Block' -or $_.DefaultOutboundAction -eq 'Block' 
    }
    
    if ($WeakProfiles.Count -eq 0) {
        Write-Host "✓ Configurações padrão de bloqueio estão adequadas" -ForegroundColor Green
    } else {
        Write-Host "! ATENÇÃO: Alguns perfis podem ter configurações não recomendadas" -ForegroundColor Yellow
    }
    Write-Host ""
    
}
catch {
    Write-Host "ERRO ao gerar resumo: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host ""
}

Write-Host "===============================================" -ForegroundColor Cyan
Write-Host "         AUDITORIA CONCLUÍDA                   " -ForegroundColor Cyan
Write-Host "===============================================" -ForegroundColor Cyan
Write-Host ""

# Opcional: Exportar relatório para arquivo
# Para descomentar as linhas abaixo e gerar um relatório em arquivo de texto:
# $OutputFile = "FirewallAudit_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
# $FirewallProfiles | Out-File -FilePath $OutputFile
# Write-Host "Relatório exportado para: $OutputFile" -ForegroundColor Green
