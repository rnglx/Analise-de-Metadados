#!/bin/bash

#Ola pentester! espero que a ferramenta te ajude. :)

cat << "EOF"
 __  __      _            _       _        
|  \/  | ___| |_ __ _  __| | __ _| |_ __ _ 
| |\/| |/ _ \ __/ _` |/ _` |/ _` | __/ _` |
| |  | |  __/ || (_| | (_| | (_| | || (_| |
|_| _|_|\___|\__\__,_|\__,_|\__,_|\__\__,_|
   / \   _ __   __ _| |_   _ _______ _ __  
  / _ \ |  _ \ / _` | | | | |_  / _ \ '__| 
 / ___ \| | | | (_| | | |_| |/ /  __/ |    
/_/   \_\_| |_|\__,_|_|\__, /___\___|_|    
                       |___/    By Lucas R. 
EOF

echo ""
echo "Desenvolvida para extrair e analisar metadados de arquivos."
echo ""


GREEN="\033[1;32m"
RED="\033[1;31m"
YELLOW="\033[1;33m"
RESET="\033[0m"
SEPARATOR="${YELLOW}---------------------------------------------------------${RESET}"

# Sua chave da API do VirusTotal
API_KEY="CHAVE-AQUI"


buscar_arquivos() {
    local dominio=$1
    local tipo_arquivo=$2
    local limite=10
    local contador=0
    local continuar="s"

    echo -e "${YELLOW}Buscando arquivos .$tipo_arquivo em $dominio...${RESET}"
    lynx --dump "https://www.google.com/search?q=site:$dominio+ext:$tipo_arquivo" | grep ".$tipo_arquivo" | cut -d "=" -f2 | egrep -v "site|google" | sed 's/...$//' > links.txt

    if [ ! -s links.txt ]; then
        echo -e "${RED}Nenhum arquivo .$tipo_arquivo encontrado no domínio $dominio.${RESET}"
        exit 1
    fi

    echo -e "${GREEN}Analisando metadados de arquivos .$tipo_arquivo...${RESET}"

    for url in $(cat links.txt); do
        wget -q $url
        arquivo=$(basename $url)

        # Pula a análise do próprio script
        if [[ "$arquivo" == "meta_analyzer.sh" ]]; then
            continue
        fi

        echo -e "\n${YELLOW}Metadados do arquivo: $arquivo${RESET}" | tee -a resultado.txt
        exiftool $arquivo | tee -a resultado.txt
        echo -e "$SEPARATOR" | tee -a resultado.txt

        # Limita downloads e questiona continuação
        ((contador++))
        if [[ $contador -eq $limite ]]; then
            echo -e "\nJá foram baixados $limite arquivos. Deseja continuar baixando mais $limite? (s/n)"
            read continuar
            if [[ $continuar != "s" ]]; then
                break
            fi
            contador=0
        fi
    done
}

# Função para enviar o arquivo para análise no VirusTotal
enviar_virus_total() {
    arquivo=$1

    # Faz o upload do arquivo para o VirusTotal
    resposta=$(curl --silent --request POST --url "https://www.virustotal.com/vtapi/v2/file/scan" \
        --form "apikey=$API_KEY" --form "file=@$arquivo")

    scan_id=$(echo $resposta | jq -r '.scan_id')
    if [ "$scan_id" == "null" ] || [ -z "$scan_id" ]; then
        echo -e "${RED}Erro ao enviar o arquivo $arquivo para o VirusTotal.${RESET}"
        return
    fi

    echo -e "${YELLOW}Analisando $arquivo no VirusTotal...${RESET}"
    
    # Aguarda resultados da análise
    sleep 20

    # Consulta o resultado da análise
    consulta_resultado=$(curl --silent --request GET --url "https://www.virustotal.com/vtapi/v2/file/report?apikey=$API_KEY&resource=$scan_id")
    
    positives=$(echo $consulta_resultado | jq -r '.positives')
    total=$(echo $consulta_resultado | jq -r '.total')

    # Tratamento para valores nulos ou inexistentes
    if [[ -z "$positives" || "$positives" == "null" || -z "$total" || "$total" == "null" ]]; then
        echo -e "${RED}Erro ao obter detecções para $arquivo.${RESET}" | tee -a resultado.txt
        return
    fi

    # Exibe o resultado de detecção com separação visual
    echo -e "$SEPARATOR"
    if [ "$positives" -eq 0 ]; then
        echo -e "${GREEN}O arquivo $arquivo está limpo ($positives/$total detecções).${RESET}" | tee -a resultado.txt
    else
        echo -e "${RED}O arquivo $arquivo é possivelmente malicioso ($positives/$total detecções).${RESET}" | tee -a resultado.txt
    fi
    echo -e "$SEPARATOR"
}

# Função para verificar arquivos no VirusTotal
verificar_virus() {
    echo -e "${YELLOW}Deseja verificar se os arquivos são maliciosos com VirusTotal? (s/n)${RESET}"
    read verificar_virus

    if [[ $verificar_virus == "s" ]]; then
        echo -e "${GREEN}Verificando arquivos no VirusTotal...${RESET}" | tee -a resultado.txt
        for file in *; do
            if [[ $file == *".pdf" || $file == *".xlsx" || $file == *".jpg" ]]; then
                enviar_virus_total $file
            fi
        done
    else
        echo -e "${GREEN}Verificação no VirusTotal ignorada.${RESET}"
    fi
}

# Função para limpar arquivos baixados após análise
limpar_arquivos() {
    echo -e "${YELLOW}Deseja excluir os arquivos baixados após a análise? (s/n)${RESET}"
    read excluir_arquivos

    if [[ $excluir_arquivos == "s" ]]; then
        rm *.pdf *.xlsx *.jpg 2>/dev/null
        echo -e "${GREEN}Arquivos removidos com sucesso.${RESET}"
    else
        echo -e "${GREEN}Os arquivos não foram removidos.${RESET}"
    fi
}

# Função principal
main() {
    if [[ $# -lt 2 ]]; then
        echo -e "${RED}Uso: $0 <domínio> <tipo_arquivo> (pdf, xlsx, jpg)${RESET}"
        exit 1
    fi

    dominio=$1
    tipo_arquivo=$2

    # Limpa arquivos antigos
    > links.txt
    > resultado.txt

    # Busca e análise de arquivos
    buscar_arquivos $dominio $tipo_arquivo

    # Verifica os arquivos no VirusTotal
    verificar_virus

    # Limpa os arquivos após análise
    limpar_arquivos

    echo -e "${YELLOW}Deseja guardar os resultados dessa busca em um .txt? (s/n)${RESET}"
    read manter_arquivos

    if [[ $manter_arquivos == "n" ]]; then
        rm links.txt resultado.txt
        echo -e "${GREEN}Arquivos removidos.${RESET}"
    fi

    echo -e "${GREEN}Processo concluído!${RESET}"
}

# Executa a função principal
main "$@"
