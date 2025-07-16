import React, { useState } from 'react';
import { motion } from 'framer-motion';
import { 
  Download, 
  Eye, 
  Trash2, 
  Filter,
  CheckCircle,
  AlertCircle,
  Clock,
  FileText,
  Hash,
  Globe
} from 'lucide-react';
import { AnalysisResult } from '../App';

interface ResultsPanelProps {
  results: AnalysisResult[];
}

const ResultsPanel: React.FC<ResultsPanelProps> = ({ results }) => {
  const [selectedResult, setSelectedResult] = useState<AnalysisResult | null>(null);
  const [filter, setFilter] = useState<'all' | 'completed' | 'running' | 'error'>('all');

  const filteredResults = results.filter(result => {
    if (filter === 'all') return true;
    return result.status === filter;
  });

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'running':
        return <Clock className="w-4 h-4 text-yellow-400" />;
      case 'completed':
        return <CheckCircle className="w-4 h-4 text-green-400" />;
      case 'error':
        return <AlertCircle className="w-4 h-4 text-red-400" />;
      default:
        return <Clock className="w-4 h-4 text-gray-400" />;
    }
  };

  const getTypeIcon = (type: string) => {
    switch (type) {
      case 'hash':
        return <Hash className="w-4 h-4" />;
      case 'webscan':
        return <Globe className="w-4 h-4" />;
      default:
        return <FileText className="w-4 h-4" />;
    }
  };

  const exportResults = (result: AnalysisResult) => {
    const data = {
      id: result.id,
      type: result.type,
      timestamp: result.timestamp,
      status: result.status,
      findings: result.findings,
      data: result.data
    };
    
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `cyberscope-${result.type}-${result.id}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-6">
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        whileInView={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.6 }}
        className="text-center"
      >
        <h2 className="text-3xl font-bold text-white mb-4">Resultados de Análisis</h2>
        <p className="text-gray-400">Historial completo de análisis realizados</p>
      </motion.div>

      {/* Filtros */}
      <div className="flex flex-wrap gap-3 justify-center">
        {[
          { key: 'all', label: 'Todos', count: results.length },
          { key: 'completed', label: 'Completados', count: results.filter(r => r.status === 'completed').length },
          { key: 'running', label: 'En Progreso', count: results.filter(r => r.status === 'running').length },
          { key: 'error', label: 'Errores', count: results.filter(r => r.status === 'error').length },
        ].map((filterOption) => (
          <button
            key={filterOption.key}
            onClick={() => setFilter(filterOption.key as any)}
            className={`flex items-center space-x-2 px-4 py-2 rounded-lg font-medium transition-all duration-200 ${
              filter === filterOption.key
                ? 'bg-cyber-500 text-white'
                : 'bg-dark-800/50 text-gray-300 hover:bg-dark-700/50'
            }`}
          >
            <Filter className="w-4 h-4" />
            <span>{filterOption.label}</span>
            <span className="bg-white/20 px-2 py-1 rounded-full text-xs">
              {filterOption.count}
            </span>
          </button>
        ))}
      </div>

      {/* Lista de Resultados */}
      <div className="grid gap-4">
        {filteredResults.map((result, index) => (
          <motion.div
            key={result.id}
            initial={{ opacity: 0, x: -20 }}
            whileInView={{ opacity: 1, x: 0 }}
            transition={{ duration: 0.5, delay: index * 0.1 }}
            className="cyber-card hover:border-cyber-400/50 transition-all duration-300"
          >
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-4">
                <div className="flex items-center space-x-2">
                  {getTypeIcon(result.type)}
                  {getStatusIcon(result.status)}
                </div>
                
                <div>
                  <h3 className="text-lg font-semibold text-white capitalize">
                    {result.type} Analysis
                  </h3>
                  <p className="text-sm text-gray-400">
                    {new Date(result.timestamp).toLocaleString()}
                  </p>
                </div>
              </div>

              <div className="flex items-center space-x-2">
                <span className={`px-3 py-1 rounded-full text-xs font-medium ${
                  result.status === 'completed' ? 'bg-green-500/20 text-green-400' :
                  result.status === 'running' ? 'bg-yellow-500/20 text-yellow-400' :
                  'bg-red-500/20 text-red-400'
                }`}>
                  {result.findings.length} hallazgos
                </span>

                <div className="flex space-x-1">
                  <button
                    onClick={() => setSelectedResult(result)}
                    className="p-2 rounded-lg text-gray-400 hover:text-cyber-400 hover:bg-dark-700 transition-colors"
                    title="Ver detalles"
                  >
                    <Eye className="w-4 h-4" />
                  </button>
                  
                  <button
                    onClick={() => exportResults(result)}
                    className="p-2 rounded-lg text-gray-400 hover:text-green-400 hover:bg-dark-700 transition-colors"
                    title="Exportar"
                  >
                    <Download className="w-4 h-4" />
                  </button>
                </div>
              </div>
            </div>

            {result.status === 'completed' && result.findings.length > 0 && (
              <div className="mt-4 pt-4 border-t border-dark-700">
                <div className="space-y-2">
                  {result.findings.slice(0, 3).map((finding, idx) => (
                    <div key={idx} className="bg-dark-700/30 p-2 rounded text-sm">
                      <code className="text-cyber-300 font-mono">{finding}</code>
                    </div>
                  ))}
                  {result.findings.length > 3 && (
                    <p className="text-xs text-gray-500 text-center">
                      +{result.findings.length - 3} más...
                    </p>
                  )}
                </div>
              </div>
            )}
          </motion.div>
        ))}
      </div>

      {filteredResults.length === 0 && (
        <div className="text-center py-12">
          <div className="text-gray-400 mb-4">
            <FileText className="w-16 h-16 mx-auto mb-4 opacity-50" />
            <p className="text-lg">No hay resultados para mostrar</p>
            <p className="text-sm">Los análisis aparecerán aquí una vez completados</p>
          </div>
        </div>
      )}

      {/* Modal de Detalles */}
      {selectedResult && (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/50 backdrop-blur-sm"
          onClick={() => setSelectedResult(null)}
        >
          <motion.div
            initial={{ scale: 0.9, opacity: 0 }}
            animate={{ scale: 1, opacity: 1 }}
            className="bg-dark-800 rounded-xl border border-dark-700 p-6 w-full max-w-4xl max-h-[80vh] overflow-y-auto"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex items-center justify-between mb-6">
              <h3 className="text-2xl font-bold text-white capitalize">
                {selectedResult.type} - Detalles Completos
              </h3>
              <button
                onClick={() => setSelectedResult(null)}
                className="p-2 rounded-lg text-gray-400 hover:text-white hover:bg-dark-700 transition-colors"
              >
                ✕
              </button>
            </div>

            <div className="space-y-6">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <span className="text-sm text-gray-400">Estado:</span>
                  <div className="flex items-center space-x-2 mt-1">
                    {getStatusIcon(selectedResult.status)}
                    <span className="text-white capitalize">{selectedResult.status}</span>
                  </div>
                </div>
                <div>
                  <span className="text-sm text-gray-400">Fecha:</span>
                  <p className="text-white mt-1">
                    {new Date(selectedResult.timestamp).toLocaleString()}
                  </p>
                </div>
              </div>

              <div>
                <h4 className="text-lg font-semibold text-white mb-3">
                  Hallazgos ({selectedResult.findings.length})
                </h4>
                <div className="space-y-2 max-h-96 overflow-y-auto">
                  {selectedResult.findings.map((finding, index) => (
                    <div key={index} className="bg-dark-700/50 p-3 rounded-lg">
                      <code className="text-sm text-cyber-300 font-mono break-all">
                        {finding}
                      </code>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </motion.div>
        </motion.div>
      )}
    </div>
  );
};

export default ResultsPanel;