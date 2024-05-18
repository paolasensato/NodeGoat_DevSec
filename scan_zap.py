import time
from zapv2 import ZAPv2

# Configurações da API do ZAP
api_key = 'superseguro'  # Substitua pela sua chave de API
zap = ZAPv2(apikey=api_key, proxies={'http': 'http://localhost:8081', 'https': 'http://localhost:8080'})

# URL do alvo
target = 'http://localhost:4001'  # Substitua pelo URL do seu alvo

# Nome da política de varredura#
scan_policy_name = 'OWASP Top 10'

try:
    # Inicia uma nova sessão no ZAP
    print("Iniciando uma nova sessão no ZAP")
    zap.core.new_session(name='NodeGoatScan', overwrite=True)

    # Configuração do contexto (opcional)
    context_name = 'NodeGoatContext'
    print(f"Criando e configurando o contexto {context_name}")
    zap.context.new_context(context_name)
    zap.context.include_in_context(context_name, target + '.*')

    # Configuração da política de varredura para OWASP Top 10
    print(f"Configurando a política de varredura {scan_policy_name}")
    policy_id = zap.ascan.add_scan_policy(scan_policy_name)

    # Configurar as regras específicas do OWASP Top 10
    owasp_top_10_rules = [40018, 90019, 40020, 10105, 10047, 10025, 90023, 10033, 20017, 10038, 40012, 40014, 90022, 90033, 40032]
    for rule_id in owasp_top_10_rules:
        try:
            zap.ascan.set_policy_alert_threshold(id=rule_id, alertthreshold='MEDIUM', scanpolicyname=scan_policy_name)
            zap.ascan.set_policy_attack_strength(id=rule_id, attackstrength='HIGH', scanpolicyname=scan_policy_name)
        except Exception as e:
            print(f"Erro ao configurar a regra {rule_id}: {e}")

    # Iniciar spidering do alvo
    print(f"Iniciando spidering do alvo {target}")
    scan_id = zap.spider.scan(target)
    while int(zap.spider.status(scan_id)) < 100:
        print(f"Spider progress: {zap.spider.status(scan_id)}%")
        time.sleep(2)
    print("Spidering completo")

    # Aguarda alguns segundos após o spidering
    time.sleep(5)

    # Iniciar a varredura ativa no alvo usando a política OWASP Top 10
    print(f"Iniciando varredura ativa no alvo {target} com a política {scan_policy_name}")
    scan_id = zap.ascan.scan(target, recurse=True, inscopeonly=True, scanpolicyname=scan_policy_name, contextid=zap.context.context(context_name)['id'])
    while int(zap.ascan.status(scan_id)) < 100:
        print(f"Scan progress: {zap.ascan.status(scan_id)}%")
        time.sleep(5)
    print("Varredura ativa completa")

    # Aguarda alguns segundos após a varredura ativa
    time.sleep(5)

    # Gerar o relatório
    print("Gerando relatório")
    with open('zap_report.html', 'w') as f:
        f.write(zap.core.htmlreport())
    print("Relatório gerado com sucesso")
except Exception as e:
    print(f"Ocorreu um erro: {e}")
