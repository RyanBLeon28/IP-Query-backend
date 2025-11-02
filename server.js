import express from "express";
import axios from "axios";
import cors from "cors";
import dotenv from 'dotenv';

dotenv.config();

const app = express();
const PORT = 5000;

app.use(cors());
app.use(express.json());

const ABUSE_API_KEY = process.env.ABUSE_API_KEY;
const VT_API_KEY = process.env.VT_API_KEY;
const IPINFO_KEY = process.env.IPINFO_KEY;

async function queryAbuseIPDB(ip) {
  try {
    const response = await axios.get("https://api.abuseipdb.com/api/v2/check", {
      params: { ipAddress: ip, maxAgeInDays: 90 },
      headers: { Key: ABUSE_API_KEY, Accept: "application/json" },
    });
    return response.data.data.abuseConfidenceScore; // Retorna pontuação (0-100)
  } catch (error) {
    console.error(`Erro no AbuseIPDB para ${ip}:`, error.message);
    return 0; // Retorna 0 em caso de erro
  }
}

async function queryVirusTotal(ip) {
  try {
    const response = await axios.get(
      `https://www.virustotal.com/api/v3/ip_addresses/${ip}`, 
      {
        headers: { 
          "x-apikey": VT_API_KEY,
          "Accept": "application/json"
        }
      }
    );
    // Retorna o número de "votos" maliciosos
    return response.data.data.attributes.last_analysis_stats.malicious;
  } catch (error) {
    // 404 no VirusTotal significa "IP nunca visto", não é um erro
    if (error.response && error.response.status === 404) {
      return 0;
    }
    console.error(`Erro no VirusTotal para ${ip}:`, error.message);
    return 0; // Retorna 0 em caso de erro
  }
}

async function aggregateIpCheck(ip) {
  try {
    // Chama AMBAS as APIs em PARALELO para economizar tempo
    const [abuseScore, vtMaliciousCount] = await Promise.all([
      queryAbuseIPDB(ip),
      queryVirusTotal(ip)
    ]);

    let vtBasedScore = vtMaliciousCount * 10;
    let finalScore = Math.max(abuseScore, vtBasedScore);
    finalScore = Math.min(100, finalScore);

    return {
      ip: ip,
      abuseScore: abuseScore,
      vtMalicious: vtMaliciousCount,
      finalScore: finalScore
    };
  } catch (error) {
    return { ip: ip, finalScore: 0, error: error.message };
  }
}

// --- ENDPOINT PRINCIPAL: Processamento em Lote (Batch) ---
app.post("/check-ip-list", async (req, res) => {
  const { ips } = req.body; // Recebe o array de IPs

  if (!ips || !Array.isArray(ips)) {
    return res.status(400).json({ error: "O corpo da requisição deve ser um objeto com um array 'ips'." });
  }

  console.log(`Processando lista de ${ips.length} IPs...`);

  try {
    const results = [];
    
    // Faz o loop DENTRO do backend
    // Este loop é sequencial (um 'await' de cada vez)
    // Isso é BOM para não estourar o limite de 4 reqs/min do VirusTotal.
    for (const ip of ips) {
      const result = await aggregateIpCheck(ip);
      results.push(result);
    }

    console.log("Processamento concluído.");
    res.json(results); // Devolve o array de resultados COMPLETO

  } catch (error) {
    console.error("Erro no processamento em lote:", error.message);
    res.status(500).json({ error: "Erro ao processar a lista de IPs" });
  }
});

// --- ENDPOINT DE LOTE GEOLOCALIZAÇÃO ---
async function queryIpInfo(query) {
  if (!IPINFO_KEY) {
    console.error("Chave do IPInfo não configurada.");
    return { ip: query, error: "Chave não configurada no servidor." };
  }
  
  // A URL base do ipinfo.io
  const url = `https://ipinfo.io/${query}/json?token=${IPINFO_KEY}`;
  
  try {
    const response = await axios.get(url);
    // Adicionamos 'query' na resposta para sabermos quem foi consultado
    return { ...response.data, query: query }; 
  } catch (error) {
    console.error(`Erro consultando IPInfo para ${query}:`, error.message);
    return { query: query, error: "Falha ao buscar dados." };
  }
}

// SUBSTITUA o endpoint /get-ip-info-list por este:
app.post("/get-ip-info-list", async (req, res) => {
  const { ips } = req.body; // 'ips' é um array de IPs e Domínios
  if (!ips || !Array.isArray(ips)) {
    return res.status(400).json({ error: "O corpo deve ser um array 'ips'." });
  }

  console.log(`Processando lista de geo-info de ${ips.length} queries...`);

  try {
    const results = [];
    // Faz o loop e chama a nova função (queryIpInfo)
    for (const query of ips) {
      const result = await queryIpInfo(query);
      results.push(result);
    }
    
    console.log("Processamento de geo-info concluído.");
    console.log("Resultado: ",results);
    res.json(results); // Envia o array de resultados

  } catch (error) {
    console.error("Erro no processamento em lote /get-ip-info-list:", error.message);
    res.status(500).json({ error: "Erro ao processar lista de geo-info." });
  }
});

async function queryIpApi(query) {
  const url = `https://ip-api.com/json/${query}`;
  try {
    const response = await axios.get(url, {
      params: {
        // Adicione os campos que seu componente precisa
        fields: 'query,country,city,region,lat,lon,isp,status,message' 
      },
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36'
      }
    });
    return response.data;
  } catch (error) {
    console.error(`Erro no ip-api para ${query}:`, error.message);
    return { query: query, status: 'fail', message: 'Erro no servidor backend' };
  }
}


// --- 2. ADICIONE A NOVA ROTA ESPECÍFICA (GET) ---
app.get("/get-geo-for-query/:query", async (req, res) => {
  const { query } = req.params;

  console.log(`Processando geo-query única para: ${query}`);
  
  try {
    // Reutiliza a função helper que já funciona
    const result = await queryIpApi(query); 
    res.json(result);
  } catch (error) {
    console.error(`Erro na query única ${query}:`, error.message);
    res.status(500).json({ error: "Erro ao processar a query." });
  }
});

app.listen(PORT, () => {
  console.log(`Servidor rodando em http://localhost:${PORT}`);
});