Este é o backend da aplicação IP Query, uma API Node.js/Express que atua como um gateway seguro. Sua função principal é proteger as chaves de APIs de terceiros (AbuseIPDB, VirusTotal, ipinfo.io), receber requisições do frontend, consultar essas APIs externas e retornar dados agregados de reputação e geolocalização.

Principais Rotas:

POST /check-ip-list: Recebe um array de IPs, consulta o AbuseIPDB e o VirusTotal, e retorna uma lista com os scores de ameaça unificados.

POST /get-ip-info-list: Recebe um array de IPs/domínios, consulta o ipinfo.io em lote e retorna os dados de geolocalização (país, loc, etc.) para o mapa de calor.

GET /get-geo-for-query/:query: Recebe um único IP ou domínio (da barra de pesquisa), resolve o DNS (se necessário) e retorna a geolocalização exata para o marcador do mapa.

GET /health: Rota simples de "health check" para monitoramento da hospedagem.

## Instalar dependências
npm install

## Rodar o backend
npm start

## O serviço está hospedado em:
https://ip-query-backend.onrender.com
