import React from 'react';
import { motion } from 'framer-motion';
import { X, Loader, CheckCircle, AlertCircle, Clock } from 'lucide-react';
import { AnalysisResult } from '../App';

interface AnalysisPanelProps {
  analysis: AnalysisResult;
  onClose: () => void;
}

const AnalysisPanel: React.FC<AnalysisPanelProps> = ({ analysis, onClose }) => {
  const getStatusIcon = () => {
    switch (analysis.status) {
      case 'running':
        return <Loader className="w-5 h-5 text-yellow-400 animate-spin" />;
      case 'completed':
        return <CheckCircle className="w-5 h-5 text-green-400" />;
      case 'error':
        return <AlertCircle className="w-5 h-5 text-red-400" />;
      default:
        return <Clock className="w-5 h-5 text-gray-400" />;
    }
  };

  const getStatusText = () => {
    switch (analysis.status) {
      case 'running':
        return 'Analizando...';
      case 'completed':
        return 'Completado';
      case 'error':
        return 'Error';
      default:
        return 'Pendiente';
    }
  };

  const getStatusColor = () => {
    switch (analysis.status) {
      case 'running':
        return 'text-yellow-400';
      case 'completed':
        return 'text-green-400';
      case 'error':
        return 'text-red-400';
      default:
        return 'text-gray-400';
    }
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, y: -20 }}
      className="cyber-card"
    >
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center space-x-3">
          {getStatusIcon()}
          <div>
            <h3 className="text-xl font-semibold text-white">
              Análisis en Progreso
            </h3>
            <p className={`text-sm ${getStatusColor()}`}>
              {getStatusText()}
            </p>
          </div>
        </div>
        <button
          onClick={onClose}
          className="p-2 rounded-lg text-gray-400 hover:text-white hover:bg-dark-700 transition-colors"
        >
          <X className="w-5 h-5" />
        </button>
      </div>

      <div className="space-y-4">
        <div className="grid grid-cols-2 gap-4">
          <div>
            <span className="text-sm text-gray-400">Tipo:</span>
            <p className="text-white font-medium capitalize">{analysis.type}</p>
          </div>
          <div>
            <span className="text-sm text-gray-400">Iniciado:</span>
            <p className="text-white font-medium">
              {new Date(analysis.timestamp).toLocaleTimeString()}
            </p>
          </div>
        </div>

        {analysis.status === 'running' && (
          <div className="space-y-3">
            <div className="flex items-center space-x-2">
              <div className="w-2 h-2 bg-cyber-400 rounded-full animate-pulse"></div>
              <span className="text-gray-300">Procesando datos...</span>
            </div>
            <div className="w-full bg-dark-700 rounded-full h-2">
              <div className="bg-gradient-to-r from-cyber-500 to-cyber-400 h-2 rounded-full animate-pulse" style={{ width: '60%' }}></div>
            </div>
          </div>
        )}

        {analysis.status === 'completed' && analysis.findings.length > 0 && (
          <div className="space-y-3">
            <h4 className="text-lg font-medium text-white">Hallazgos Preliminares:</h4>
            <div className="space-y-2 max-h-40 overflow-y-auto">
              {analysis.findings.slice(0, 5).map((finding, index) => (
                <div key={index} className="bg-dark-700/50 p-3 rounded-lg">
                  <code className="text-sm text-cyber-300 font-mono">{finding}</code>
                </div>
              ))}
              {analysis.findings.length > 5 && (
                <p className="text-sm text-gray-400 text-center">
                  +{analysis.findings.length - 5} hallazgos más...
                </p>
              )}
            </div>
          </div>
        )}
      </div>
    </motion.div>
  );
};

export default AnalysisPanel;