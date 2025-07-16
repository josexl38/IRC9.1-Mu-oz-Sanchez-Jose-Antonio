import React, { useState } from 'react';
import { motion } from 'framer-motion';
import { 
  Hash, 
  Search, 
  Image, 
  FileText, 
  Globe, 
  Shield, 
  Eye,
  Fingerprint,
  Wifi,
  Database,
  Lock,
  Zap
} from 'lucide-react';
import ToolModal from './ToolModal';

interface Tool {
  id: string;
  name: string;
  description: string;
  icon: React.ComponentType<any>;
  category: string;
  color: string;
}

interface ToolsGridProps {
  onStartAnalysis: (type: string, data: any) => void;
}

const ToolsGrid: React.FC<ToolsGridProps> = ({ onStartAnalysis }) => {
  const [selectedTool, setSelectedTool] = useState<Tool | null>(null);

  const tools: Tool[] = [
    {
      id: 'hash',
      name: 'Hash de Archivos',
      description: 'Calcula MD5, SHA1, SHA256 de archivos y directorios',
      icon: Hash,
      category: 'Forense',
      color: 'from-blue-500 to-blue-600'
    },
    {
      id: 'search',
      name: 'Buscar Sospechosos',
      description: 'Encuentra archivos potencialmente maliciosos',
      icon: Search,
      category: 'Forense',
      color: 'from-red-500 to-red-600'
    },
    {
      id: 'exif',
      name: 'Metadatos EXIF',
      description: 'Extrae metadatos de imágenes',
      icon: Image,
      category: 'Forense',
      color: 'from-green-500 to-green-600'
    },
    {
      id: 'pdf',
      name: 'Metadatos PDF',
      description: 'Analiza metadatos de documentos PDF',
      icon: FileText,
      category: 'Forense',
      color: 'from-purple-500 to-purple-600'
    },
    {
      id: 'webscan',
      name: 'Web Scanner',
      description: 'Analiza cabeceras y contenido de sitios web',
      icon: Globe,
      category: 'Web',
      color: 'from-cyan-500 to-cyan-600'
    },
    {
      id: 'dirscan',
      name: 'Directory Fuzzing',
      description: 'Descubre directorios y archivos ocultos',
      icon: Eye,
      category: 'Web',
      color: 'from-orange-500 to-orange-600'
    },
    {
      id: 'ioc',
      name: 'Extractor IoCs',
      description: 'Encuentra indicadores de compromiso',
      icon: Fingerprint,
      category: 'Análisis',
      color: 'from-pink-500 to-pink-600'
    },
    {
      id: 'whois',
      name: 'WHOIS Lookup',
      description: 'Información de registro de dominios',
      icon: Database,
      category: 'OSINT',
      color: 'from-indigo-500 to-indigo-600'
    },
    {
      id: 'ipinfo',
      name: 'IP Information',
      description: 'Geolocalización y datos de IPs',
      icon: Wifi,
      category: 'OSINT',
      color: 'from-teal-500 to-teal-600'
    },
    {
      id: 'logincheck',
      name: 'Login Detector',
      description: 'Detecta formularios de autenticación',
      icon: Lock,
      category: 'Web',
      color: 'from-yellow-500 to-yellow-600'
    }
  ];

  const categories = ['Todos', 'Forense', 'Web', 'Análisis', 'OSINT'];
  const [activeCategory, setActiveCategory] = useState('Todos');

  const filteredTools = activeCategory === 'Todos' 
    ? tools 
    : tools.filter(tool => tool.category === activeCategory);

  return (
    <>
      <div className="mb-8">
        <div className="flex flex-wrap justify-center gap-4">
          {categories.map((category) => (
            <button
              key={category}
              onClick={() => setActiveCategory(category)}
              className={`px-6 py-2 rounded-full font-medium transition-all duration-200 ${
                activeCategory === category
                  ? 'bg-cyber-500 text-white shadow-lg shadow-cyber-500/25'
                  : 'bg-dark-800/50 text-gray-300 hover:bg-dark-700/50 hover:text-white'
              }`}
            >
              {category}
            </button>
          ))}
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-6">
        {filteredTools.map((tool, index) => (
          <motion.div
            key={tool.id}
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, delay: index * 0.1 }}
            whileHover={{ scale: 1.05 }}
            className="cyber-card cursor-pointer group"
            onClick={() => setSelectedTool(tool)}
          >
            <div className="flex flex-col items-center text-center space-y-4">
              <div className={`p-4 rounded-xl bg-gradient-to-r ${tool.color} shadow-lg group-hover:shadow-xl transition-all duration-300`}>
                <tool.icon className="w-8 h-8 text-white" />
              </div>
              
              <div>
                <h3 className="text-lg font-semibold text-white mb-2">{tool.name}</h3>
                <p className="text-gray-400 text-sm leading-relaxed">{tool.description}</p>
              </div>
              
              <div className="flex items-center space-x-2">
                <span className="text-xs bg-cyber-500/20 text-cyber-400 px-2 py-1 rounded-full">
                  {tool.category}
                </span>
                <Zap className="w-4 h-4 text-cyber-400 opacity-0 group-hover:opacity-100 transition-opacity" />
              </div>
            </div>
          </motion.div>
        ))}
      </div>

      {selectedTool && (
        <ToolModal
          tool={selectedTool}
          onClose={() => setSelectedTool(null)}
          onStartAnalysis={onStartAnalysis}
        />
      )}
    </>
  );
};

export default ToolsGrid;