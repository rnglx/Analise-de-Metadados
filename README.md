### Metadata Analyzer - Análise de Metadados

é uma ferramenta desenvolvida para realizar busca passiva e automatizada de metadados em arquivos públicos disponíveis em domínios alvo. 
Ela foi projetada para facilitar a coleta de informações importantes em fases iniciais de pentests, com a possibilidade de análise adicional usando o VirusTotal.

##### Funcionalidades
* Busca passiva por arquivos de interesse (.pdf, .xlsx, .jpg) em um domínio-alvo.
* Extração automática de metadados utilizando o ExifTool.
* Análise de segurança no VirusTotal (sem necessidade de APIs externas, apenas chave pessoal).
* Relatórios organizados com informações detalhadas dos arquivos analisados.

--------------------------------------------------------------------------------------------------------------------------------------

##### Instalação das Dependências:
Para instalar as dependências necessárias:

sudo apt-get update
sudo apt-get install exiftool lynx curl jq

--------------------------------------------------------------------------------------------------------------------------------------

### Instalação da Ferramenta
Clone este repositório:

git clone https://github.com/rnglx/Analise-de-Metadados.git

Acesse a pasta do projeto:
cd Analise-de-Metadados

Dê permissão de execução ao script:
chmod +x meta_analyzer.sh

--------------------------------------------------------------------------------------------------------------------------------------

### Importante caso queira usar a verificaçao do virus total:

Adicione sua chave da API do VirusTotal no script:
No arquivo meta_analyzer.sh, adicione sua chave da API na variável API_KEY.

nano meta_analyzer.sh

--------------------------------------------------------------------------------------------------------------------------------------

### Uso:

Execute o script passando o domínio e o tipo de arquivo que deseja analisar:

./analise_metadados.sh <domínio> <tipo_arquivo>

<domínio>: O domínio onde os arquivos serão buscados (ex: example.com).
<tipo_arquivo>: O tipo de arquivo a ser buscado (ex: pdf, xlsx, jpg).

#####Exemplo:
./analise_metadados.sh example.com pdf
