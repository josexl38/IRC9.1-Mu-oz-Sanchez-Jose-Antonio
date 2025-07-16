import React, { useState } from 'react';
import { motion } from 'framer-motion';
import Header from './components/Header';
import Hero from './components/Hero';
import ToolsGrid from './components/ToolsGrid';
import AnalysisPanel from './components/AnalysisPanel';
import ResultsPanel from './components/ResultsPanel';
import Footer from './components/Footer';

export interface AnalysisResult {
  id: string;
  type: string;
  timestamp: string;
  status: 'running' | 'completed' | 'error';
  data: any;
  findings: string[];
}

function App() {
  const [activeAnalysis, setActiveAnalysis] = useState<string | null>(null);
  const [results, setResults] = useState<AnalysisResult[]>([]);

  const handleStartAnalysis = (type: string, data: any) => {
    const newAnalysis: AnalysisResult = {
      id: Date.now().toString(),
      type,
      timestamp: new Date().toISOString(),
      status: 'running',
      data,
      findings: []
    };

    setResults(prev => [newAnalysis, ...prev]);
    setActiveAnalysis(newAnalysis.id);

    // Simular análisis
    setTimeout(() => {
      setResults(prev => prev.map(result => 
        result.id === newAnalysis.id 
          ? { 
              ...result, 
              status: 'completed',
              findings: generateMockFindings(type, data)
            }
          : result
      ));
    }, 3000);
  };

  const generateMockFindings = (type: string, data: any): string[] => {
    const findings = [];
    
    switch (type) {
      case 'hash':
        findings.push(`[HASH] MD5 - ${data.filename}: a1b2c3d4e5f6789012345678901234567`);
        findings.push(`[HASH] SHA256 - ${data.filename}: 1a2b3c4d5e6f7890123456789012345678901234567890123456789012345678`);
        findings.push(`[FILE_SIZE] ${data.filename}: 2048 bytes`);
        break;
      case 'webscan':
        findings.push(`[WEBSCAN] Código de estado: 200`);
        findings.push(`[WEBHEADER_MISSING] Content-Security-Policy no está presente`);
        findings.push(`[WEBHEADER] X-Frame-Options: SAMEORIGIN`);
        findings.push(`[IOC] URL: https://example.com/api/data`);
        break;
      case 'ioc':
        findings.push(`[IOC] IP: 192.168.1.1`);
        findings.push(`[IOC] EMAIL: admin@example.com`);
        findings.push(`[IOC] URL: https://malicious-site.com`);
        break;
      default:
        findings.push(`[INFO] Análisis ${type} completado exitosamente`);
    }
    
    return findings;
  };

  return (
    <div className="min-h-screen bg-dark-900">
      <Header />
      
      <main className="relative">
        <Hero />
        
        <section id="tools" className="py-20">
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              whileInView={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.6 }}
              className="text-center mb-16"
            >
              <h2 className="text-4xl font-bold text-white mb-4">
                Herramientas de Análisis
              </h2>
              <p className="text-xl text-gray-400 max-w-3xl mx-auto">
                Suite completa de herramientas forenses digitales para análisis de archivos, 
                web scanning, extracción de IoCs y más.
              </p>
            </motion.div>
            
            <ToolsGrid onStartAnalysis={handleStartAnalysis} />
          </div>
        </section>

        {activeAnalysis && (
          <section className="py-20 bg-dark-800/30">
            <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
              <AnalysisPanel 
                analysis={results.find(r => r.id === activeAnalysis)!}
                onClose={() => setActiveAnalysis(null)}
              />
            </div>
          </section>
        )}

        {results.length > 0 && (
          <section id="results" className="py-20">
            <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
              <ResultsPanel results={results} />
            </div>
          </section>
        )}
      </main>

      <Footer />
    </div>
  );
}

export default App;