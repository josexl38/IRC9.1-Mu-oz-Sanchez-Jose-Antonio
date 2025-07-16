import React, { useState } from 'react';
import { motion } from 'framer-motion';
import { X, Play, Upload, Link, Type } from 'lucide-react';

interface Tool {
  id: string;
  name: string;
  description: string;
  icon: React.ComponentType<any>;
  category: string;
  color: string;
}

interface ToolModalProps {
  tool: Tool;
  onClose: () => void;
  onStartAnalysis: (type: string, data: any) => void;
}

const ToolModal: React.FC<ToolModalProps> = ({ tool, onClose, onStartAnalysis }) => {
  const [inputData, setInputData] = useState<any>({});
  const [inputType, setInputType] = useState<'file' | 'text' | 'url'>('text');

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    onStartAnalysis(tool.id, { ...inputData, inputType });
    onClose();
  };

  const getInputFields = () => {
    switch (tool.id) {
      case 'hash':
        return (
          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">
                Archivo o Directorio
              </label>
              <input
                type="text"
                placeholder="/ruta/al/archivo"
                className="w-full px-4 py-2 bg-dark-800 border border-dark-600 rounded-lg text-white focus:border-cyber-500 focus:outline-none"
                onChange={(e) => setInputData({ ...inputData, filename: e.target.value })}
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">
                Algoritmos
              </label>
              <div className="flex space-x-4">
                {['md5', 'sha1', 'sha256'].map((algo) => (
                  <label key={algo} className="flex items-center">
                    <input
                      type="checkbox"
                      defaultChecked
                      className="mr-2 text-cyber-500"
                      onChange={(e) => {
                        const algos = inputData.algorithms || ['md5', 'sha1', 'sha256'];
                        if (e.target.checked) {
                          setInputData({ ...inputData, algorithms: [...algos, algo] });
                        } else {
                          setInputData({ ...inputData, algorithms: algos.filter(a => a !== algo) });
                        }
                      }}
                    />
                    <span className="text-gray-300 uppercase">{algo}</span>
                  </label>
                ))}
              </div>
            </div>
          </div>
        );

      case 'webscan':
        return (
          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">
                URL del sitio web
              </label>
              <input
                type="url"
                placeholder="https://ejemplo.com"
                className="w-full px-4 py-2 bg-dark-800 border border-dark-600 rounded-lg text-white focus:border-cyber-500 focus:outline-none"
                onChange={(e) => setInputData({ ...inputData, url: e.target.value })}
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">
                Timeout (segundos)
              </label>
              <input
                type="number"
                defaultValue={10}
                min={1}
                max={60}
                className="w-full px-4 py-2 bg-dark-800 border border-dark-600 rounded-lg text-white focus:border-cyber-500 focus:outline-none"
                onChange={(e) => setInputData({ ...inputData, timeout: parseInt(e.target.value) })}
              />
            </div>
          </div>
        );

      case 'ioc':
        return (
          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">
                Texto a analizar
              </label>
              <textarea
                rows={6}
                placeholder="Pega aquí el texto, logs o contenido a analizar..."
                className="w-full px-4 py-2 bg-dark-800 border border-dark-600 rounded-lg text-white focus:border-cyber-500 focus:outline-none resize-none"
                onChange={(e) => setInputData({ ...inputData, content: e.target.value })}
              />
            </div>
          </div>
        );

      case 'whois':
        return (
          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">
                Dominio
              </label>
              <input
                type="text"
                placeholder="ejemplo.com"
                className="w-full px-4 py-2 bg-dark-800 border border-dark-600 rounded-lg text-white focus:border-cyber-500 focus:outline-none"
                onChange={(e) => setInputData({ ...inputData, domain: e.target.value })}
              />
            </div>
          </div>
        );

      case 'ipinfo':
        return (
          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">
                Dirección IP
              </label>
              <input
                type="text"
                placeholder="8.8.8.8"
                className="w-full px-4 py-2 bg-dark-800 border border-dark-600 rounded-lg text-white focus:border-cyber-500 focus:outline-none"
                onChange={(e) => setInputData({ ...inputData, ip: e.target.value })}
              />
            </div>
          </div>
        );

      default:
        return (
          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">
                Entrada
              </label>
              <input
                type="text"
                placeholder="Ingresa los datos necesarios..."
                className="w-full px-4 py-2 bg-dark-800 border border-dark-600 rounded-lg text-white focus:border-cyber-500 focus:outline-none"
                onChange={(e) => setInputData({ ...inputData, input: e.target.value })}
              />
            </div>
          </div>
        );
    }
  };

  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/50 backdrop-blur-sm"
      onClick={onClose}
    >
      <motion.div
        initial={{ scale: 0.9, opacity: 0 }}
        animate={{ scale: 1, opacity: 1 }}
        exit={{ scale: 0.9, opacity: 0 }}
        className="bg-dark-800 rounded-xl border border-dark-700 p-6 w-full max-w-md"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between mb-6">
          <div className="flex items-center space-x-3">
            <div className={`p-2 rounded-lg bg-gradient-to-r ${tool.color}`}>
              <tool.icon className="w-6 h-6 text-white" />
            </div>
            <div>
              <h3 className="text-lg font-semibold text-white">{tool.name}</h3>
              <p className="text-sm text-gray-400">{tool.category}</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-2 rounded-lg text-gray-400 hover:text-white hover:bg-dark-700 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        <p className="text-gray-300 mb-6">{tool.description}</p>

        <form onSubmit={handleSubmit} className="space-y-6">
          {getInputFields()}

          <div className="flex space-x-3 pt-4">
            <button
              type="button"
              onClick={onClose}
              className="flex-1 px-4 py-2 bg-dark-700 text-gray-300 rounded-lg hover:bg-dark-600 transition-colors"
            >
              Cancelar
            </button>
            <button
              type="submit"
              className="flex-1 cyber-button flex items-center justify-center space-x-2"
            >
              <Play className="w-4 h-4" />
              <span>Ejecutar</span>
            </button>
          </div>
        </form>
      </motion.div>
    </motion.div>
  );
};

export default ToolModal;