import React from 'react';
import { Shield, Github, Mail, ExternalLink } from 'lucide-react';

const Footer: React.FC = () => {
  return (
    <footer className="bg-dark-900 border-t border-dark-700/50 py-12">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-8">
          {/* Logo y descripción */}
          <div className="col-span-1 md:col-span-2">
            <div className="flex items-center space-x-3 mb-4">
              <div className="relative">
                <Shield className="w-8 h-8 text-cyber-400" />
                <div className="absolute inset-0 bg-cyber-400/20 rounded-full blur-md"></div>
              </div>
              <span className="text-xl font-bold text-white">CyberScope</span>
              <span className="text-xs bg-cyber-500/20 text-cyber-400 px-2 py-1 rounded-full">
                v2.0
              </span>
            </div>
            <p className="text-gray-400 mb-4 max-w-md">
              Herramienta avanzada de análisis forense digital y ciberseguridad. 
              Desarrollada para profesionales de la seguridad informática.
            </p>
            <div className="flex space-x-4">
              <a
                href="#"
                className="text-gray-400 hover:text-cyber-400 transition-colors"
                title="GitHub"
              >
                <Github className="w-5 h-5" />
              </a>
              <a
                href="#"
                className="text-gray-400 hover:text-cyber-400 transition-colors"
                title="Email"
              >
                <Mail className="w-5 h-5" />
              </a>
            </div>
          </div>

          {/* Herramientas */}
          <div>
            <h3 className="text-white font-semibold mb-4">Herramientas</h3>
            <ul className="space-y-2">
              <li><a href="#" className="text-gray-400 hover:text-cyber-400 transition-colors">Hash de Archivos</a></li>
              <li><a href="#" className="text-gray-400 hover:text-cyber-400 transition-colors">Web Scanner</a></li>
              <li><a href="#" className="text-gray-400 hover:text-cyber-400 transition-colors">Extractor IoCs</a></li>
              <li><a href="#" className="text-gray-400 hover:text-cyber-400 transition-colors">OSINT Tools</a></li>
            </ul>
          </div>

          {/* Recursos */}
          <div>
            <h3 className="text-white font-semibold mb-4">Recursos</h3>
            <ul className="space-y-2">
              <li>
                <a href="#" className="text-gray-400 hover:text-cyber-400 transition-colors flex items-center">
                  Documentación
                  <ExternalLink className="w-3 h-3 ml-1" />
                </a>
              </li>
              <li>
                <a href="#" className="text-gray-400 hover:text-cyber-400 transition-colors flex items-center">
                  API Reference
                  <ExternalLink className="w-3 h-3 ml-1" />
                </a>
              </li>
              <li>
                <a href="#" className="text-gray-400 hover:text-cyber-400 transition-colors">
                  Ejemplos
                </a>
              </li>
              <li>
                <a href="#" className="text-gray-400 hover:text-cyber-400 transition-colors">
                  Soporte
                </a>
              </li>
            </ul>
          </div>
        </div>

        <div className="border-t border-dark-700/50 mt-8 pt-8 flex flex-col md:flex-row justify-between items-center">
          <p className="text-gray-400 text-sm">
            © 2024 CyberScope. Desarrollado para análisis forense digital.
          </p>
          <div className="flex space-x-6 mt-4 md:mt-0">
            <a href="#" className="text-gray-400 hover:text-cyber-400 transition-colors text-sm">
              Términos de Uso
            </a>
            <a href="#" className="text-gray-400 hover:text-cyber-400 transition-colors text-sm">
              Privacidad
            </a>
            <a href="#" className="text-gray-400 hover:text-cyber-400 transition-colors text-sm">
              Licencia
            </a>
          </div>
        </div>
      </div>
    </footer>
  );
};

export default Footer;