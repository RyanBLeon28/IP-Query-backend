import express from "express";
import axios from "axios";
import cors from "cors";
import dotenv from 'dotenv';
import dns from 'dns';
import { promisify } from 'util';

dotenv.config();

// Converte a função de callback do dns para uma que usa Promises (async/await)
const dnsLookup = promisify(dns.lookup);

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
    if (error.response && error.response.status === 404) {
      return 0;
    }
    console.error(`Erro no VirusTotal para ${ip}:`, error.message);
    return 0; 
  }
}

async function aggregateIpCheck(ip) {
  try {
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
    
    for (const ip of ips) {
      const result = await aggregateIpCheck(ip);
      results.push(result);
    }

    // console.log("Processamento concluído.");
    res.json(results); 

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
  let ipParaConsultar;

  // Verifica se a query já é um IP
  const isIP = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(query);

  if (isIP) {
    ipParaConsultar = query; // Já é um IP, pode usar
  } else {
    // NÃO é um IP (é um domínio), então resolvemos o DNS primeiro
    try {
      const { address } = await dnsLookup(query);
      ipParaConsultar = address;
      console.log(`Domínio ${query} resolvido para IP: ${ipParaConsultar}`);
    } catch (dnsError) {
      console.error(`Erro no DNS lookup para ${query}:`, dnsError.message);
      return { query: query, error: "Falha ao resolver o domínio (DNS)." };
    }
  }

  const url = `https://ipinfo.io/${ipParaConsultar}/json?token=${IPINFO_KEY}`;

  try {
    const response = await axios.get(url);
    return { ...response.data, query: query }; 
  } catch (error) {
    console.error(`Erro consultando IPInfo para ${ipParaConsultar}:`, error.message);
    return { query: query, ip: ipParaConsultar, error: "Falha ao buscar dados de geolocalização para o IP." };
  }
}

app.post("/get-ip-info-list", async (req, res) => {
  const { ips } = req.body; 
  if (!ips || !Array.isArray(ips)) {
    return res.status(400).json({ error: "O corpo deve ser um array 'ips'." });
  }

  console.log(`Processando lista de geo-info de ${ips.length} queries...`);

  try {
    const results = [];
    
    for (const query of ips) {
      const result = await queryIpInfo(query);
      results.push(result);
    }
    
    // console.log("Resultado: ",results);
    res.json(results); // Envia o array de resultados

  } catch (error) {
    console.error("Erro no processamento em lote /get-ip-info-list:", error.message);
    res.status(500).json({ error: "Erro ao processar lista de geo-info." });
  }
});

app.get("/health", (req, res) => {
  res.status(200).send("OK");
});

app.listen(PORT, () => {
  console.log(`Servidor rodando em http://localhost:${PORT}`);
});