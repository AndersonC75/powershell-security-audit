<#
.SYNOPSIS
    Script de Auditoria de Associação de Usuários a Grupos Locais
    
.DESCRIPTION
    Este script realiza uma auditoria completa dos usuários locais do sistema,
    listando suas associações a grupos e destacando especialmente os membros
    do grupo Administradores. Útil para verificação de conformidade de segurança
    e identificação de privilégios administrativos.
    
.NOTES
    Autor: Sistema de Auditoria de Segurança
    Versão: 1.0
    Requer: Privilégios administrativos para acesso completo
    Data: $(Get-Date -Format 'dd/MM/yyyy')
#>

# Função para escrever logs com cores para melhor visualização
function Write-AuditLog {
    param(
        [string]$Message,
        [string]$Type = "Info"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    
    switch ($Type) {
        "Error" { 
            Write-Host "[$timestamp] [ERRO] $Message" -ForegroundColor Red
        }
        "Warning" { 
            Write-Host "[$timestamp] [AVISO] $Message" -ForegroundColor Yellow
        }
        "Success" { 
            Write-Host "[$timestamp] [SUCESSO] $Message" -ForegroundColor Green
        }
        "Critical" { 
            Write-Host "[$timestamp] [CRÍTICO] $Message" -ForegroundColor Magenta
        }
        default { 
            Write-Host "[$timestamp] [INFO] $Message" -ForegroundColor Cyan
        }
    }
}

# Função para obter todos os usuários locais do sistema
function Get-LocalUsers {
    try {
        Write-AuditLog "Obtendo lista de usuários locais..." "Info"
        
        # Usando Get-LocalUser (disponível no PowerShell 5.1+)
        if (Get-Command Get-LocalUser -ErrorAction SilentlyContinue) {
            return Get-LocalUser | Where-Object { $_.Enabled -eq $true }
        }
        # Fallback para versões mais antigas usando WMI
        else {
            return Get-WmiObject -Class Win32_UserAccount -Filter "LocalAccount=True and Disabled=False"
        }
    }
    catch {
        Write-AuditLog "Erro ao obter usuários locais: $($_.Exception.Message)" "Error"
        return $null
    }
}

# Função para obter todos os grupos locais
function Get-LocalGroups {
    try {
        Write-AuditLog "Obtendo lista de grupos locais..." "Info"
        
        # Usando Get-LocalGroup (disponível no PowerShell 5.1+)
        if (Get-Command Get-LocalGroup -ErrorAction SilentlyContinue) {
            return Get-LocalGroup
        }
        # Fallback para versões mais antigas usando WMI
        else {
            return Get-WmiObject -Class Win32_Group -Filter "LocalAccount=True"
        }
    }
    catch {
        Write-AuditLog "Erro ao obter grupos locais: $($_.Exception.Message)" "Error"
        return $null
    }
}

# Função para obter membros de um grupo específico
function Get-GroupMembers {
    param(
        [string]$GroupName
    )
    
    try {
        # Usando Get-LocalGroupMember (disponível no PowerShell 5.1+)
        if (Get-Command Get-LocalGroupMember -ErrorAction SilentlyContinue) {
            return Get-LocalGroupMember -Group $GroupName -ErrorAction SilentlyContinue
        }
        # Fallback usando net localgroup
        else {
            $members = net localgroup "$GroupName" 2>$null | Where-Object { $_ -and $_ -notmatch "^(Alias name|Comment|Members|The command completed)" -and $_ -notmatch "^-+$" }
            return $members | Where-Object { $_.Trim() -ne "" }
        }
    }
    catch {
        Write-AuditLog "Erro ao obter membros do grupo '$GroupName': $($_.Exception.Message)" "Warning"
        return $null
    }
}

# Função principal para auditoria de associação de usuários a grupos
function Start-UserGroupMembershipAudit {
    Write-AuditLog "=== INICIANDO AUDITORIA DE ASSOCIAÇÃO DE USUÁRIOS A GRUPOS ===" "Success"
    Write-AuditLog "Computador: $env:COMPUTERNAME" "Info"
    Write-AuditLog "Data/Hora: $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')" "Info"
    Write-Host "`n" -NoNewline
    
    # Obter usuários e grupos locais
    $localUsers = Get-LocalUsers
    $localGroups = Get-LocalGroups
    
    if (-not $localUsers) {
        Write-AuditLog "Não foi possível obter usuários locais. Interrompendo auditoria." "Error"
        return
    }
    
    if (-not $localGroups) {
        Write-AuditLog "Não foi possível obter grupos locais. Interrompendo auditoria." "Error"
        return
    }
    
    # Criar estrutura para armazenar resultados
    $auditResults = @{}
    $adminMembers = @()
    
    Write-AuditLog "Encontrados $($localUsers.Count) usuários locais ativos" "Info"
    Write-AuditLog "Encontrados $($localGroups.Count) grupos locais" "Info"
    Write-Host "`n" -NoNewline
    
    # Para cada usuário, verificar associações a grupos
    foreach ($user in $localUsers) {
        $userName = if ($user.Name) { $user.Name } else { $user.UserName }
        $auditResults[$userName] = @()
        
        Write-AuditLog "Verificando associações para usuário: $userName" "Info"
        
        # Verificar cada grupo para ver se o usuário é membro
        foreach ($group in $localGroups) {
            $groupName = if ($group.Name) { $group.Name } else { $group.GroupName }
            $members = Get-GroupMembers -GroupName $groupName
            
            if ($members) {
                # Verificar se o usuário está na lista de membros
                $isMember = $false
                foreach ($member in $members) {
                    $memberName = if ($member.Name) { $member.Name } else { $member.ToString().Trim() }
                    
                    if ($memberName -match $userName -or $memberName -eq $userName) {
                        $isMember = $true
                        break
                    }
                }
                
                if ($isMember) {
                    $auditResults[$userName] += $groupName
                    
                    # Verificar se é membro do grupo Administradores
                    if ($groupName -match "Administr" -or $groupName -eq "Administrators") {
                        $adminMembers += $userName
                        Write-AuditLog "ATENÇÃO: '$userName' é membro do grupo Administradores!" "Critical"
                    }
                }
            }
        }
    }
    
    # Exibir resultados da auditoria
    Write-Host "`n" -NoNewline
    Write-AuditLog "=== RESULTADOS DA AUDITORIA ===" "Success"
    Write-Host "`n" -NoNewline
    
    foreach ($user in $auditResults.Keys) {
        Write-Host "Usuário: $user" -ForegroundColor White -BackgroundColor DarkBlue
        
        if ($auditResults[$user].Count -gt 0) {
            Write-Host "  Grupos:" -ForegroundColor Yellow
            foreach ($group in $auditResults[$user]) {
                if ($group -match "Administr" -or $group -eq "Administrators") {
                    Write-Host "    ★ $group" -ForegroundColor Red -BackgroundColor Yellow
                } else {
                    Write-Host "    • $group" -ForegroundColor Green
                }
            }
        } else {
            Write-Host "  Nenhuma associação a grupos encontrada" -ForegroundColor Gray
        }
        Write-Host "`n" -NoNewline
    }
    
    # Resumo de segurança
    Write-AuditLog "=== RESUMO DE SEGURANÇA ===" "Success"
    Write-Host "`n" -NoNewline
    
    if ($adminMembers.Count -gt 0) {
        Write-AuditLog "ALERTA DE SEGURANÇA: $($adminMembers.Count) usuário(s) com privilégios administrativos encontrado(s):" "Critical"
        foreach ($admin in $adminMembers) {
            Write-Host "  ⚠️  $admin" -ForegroundColor Red
        }
        Write-Host "`n" -NoNewline
        Write-AuditLog "RECOMENDAÇÃO: Verifique se todos estes usuários realmente precisam de privilégios administrativos" "Warning"
    } else {
        Write-AuditLog "Nenhum usuário local com privilégios administrativos identificado" "Success"
    }
    
    # Estatísticas finais
    Write-Host "`n" -NoNewline
    Write-AuditLog "=== ESTATÍSTICAS ===" "Info"
    Write-AuditLog "Total de usuários auditados: $($localUsers.Count)" "Info"
    Write-AuditLog "Total de grupos verificados: $($localGroups.Count)" "Info"
    Write-AuditLog "Usuários com privilégios administrativos: $($adminMembers.Count)" "Info"
    
    # Salvar relatório em arquivo (opcional)
    $reportPath = "$env:USERPROFILE\Desktop\UserGroupMembership_Audit_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
    
    try {
        $reportContent = @()
        $reportContent += "=== RELATÓRIO DE AUDITORIA DE ASSOCIAÇÃO DE USUÁRIOS A GRUPOS ==="
        $reportContent += "Computador: $env:COMPUTERNAME"
        $reportContent += "Data/Hora: $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')"
        $reportContent += ""
        
        foreach ($user in $auditResults.Keys) {
            $reportContent += "Usuário: $user"
            if ($auditResults[$user].Count -gt 0) {
                $reportContent += "  Grupos:"
                foreach ($group in $auditResults[$user]) {
                    if ($group -match "Administr" -or $group -eq "Administrators") {
                        $reportContent += "    ★ $group (ADMINISTRATIVO)"
                    } else {
                        $reportContent += "    • $group"
                    }
                }
            } else {
                $reportContent += "  Nenhuma associação a grupos encontrada"
            }
            $reportContent += ""
        }
        
        $reportContent += "=== RESUMO DE SEGURANÇA ==="
        if ($adminMembers.Count -gt 0) {
            $reportContent += "ALERTA: $($adminMembers.Count) usuário(s) com privilégios administrativos:"
            foreach ($admin in $adminMembers) {
                $reportContent += "  - $admin"
            }
        } else {
            $reportContent += "Nenhum usuário local com privilégios administrativos identificado"
        }
        
        $reportContent | Out-File -FilePath $reportPath -Encoding UTF8
        Write-AuditLog "Relatório salvo em: $reportPath" "Success"
        
    } catch {
        Write-AuditLog "Erro ao salvar relatório: $($_.Exception.Message)" "Warning"
    }
    
    Write-Host "`n" -NoNewline
    Write-AuditLog "=== AUDITORIA CONCLUÍDA ===" "Success"
}

# Verificar se está sendo executado como administrador
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")

if (-not $isAdmin) {
    Write-AuditLog "AVISO: Script não está sendo executado como administrador" "Warning"
    Write-AuditLog "Algumas informações podem não estar disponíveis" "Warning"
    Write-Host "`n" -NoNewline
}

# Executar a auditoria
Start-UserGroupMembershipAudit
