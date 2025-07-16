import React from 'react';
import { motion } from 'framer-motion';
import { Shield, Zap, Eye, Lock } from 'lucide-react';

const Hero: React.FC = () => {
  const features = [
    { icon: Shield, text: 'Análisis Forense' },
    { icon: Zap, text: 'Detección Rápida' },
    { icon: Eye, text: 'Monitoreo Web' },
    { icon: Lock, text: 'Seguridad Avanzada' },
  ];

  return (
    <section id="home" className="relative min-h-screen flex items-center justify-center overflow-hidden">
      {/* Background Effects */}
      <div className="absolute inset-0">
        <div className="absolute inset-0 bg-gradient-to-br from-dark-900 via-dark-800 to-dark-900"></div>
        <div className="absolute top-1/4 left-1/4 w-96 h-96 bg-cyber-500/10 rounded-full blur-3xl"></div>
        <div className="absolute bottom-1/4 right-1/4 w-96 h-96 bg-cyber-400/5 rounded-full blur-3xl"></div>
      </div>

      {/* Scanning Line Effect */}
      <div className="absolute inset-0 overflow-hidden">
        <div className="scan-line"></div>
      </div>

      <div className="relative z-10 max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 text-center">
        <motion.div
          initial={{ opacity: 0, y: 30 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.8 }}
        >
          <h1 className="text-5xl md:text-7xl font-bold text-white mb-6">
            <span className="bg-gradient-to-r from-cyber-400 to-cyber-600 bg-clip-text text-transparent">
              CyberScope
            </span>
          </h1>
          
          <p className="text-xl md:text-2xl text-gray-300 mb-8 max-w-3xl mx-auto">
            Herramienta avanzada de análisis forense digital y ciberseguridad
          </p>
          
          <p className="text-lg text-gray-400 mb-12 max-w-2xl mx-auto">
            Analiza archivos, extrae metadatos, detecta IoCs, escanea sitios web y más. 
            Todo desde una interfaz moderna y intuitiva.
          </p>
        </motion.div>

        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.8, delay: 0.2 }}
          className="flex flex-wrap justify-center gap-6 mb-12"
        >
          {features.map((feature, index) => (
            <div
              key={index}
              className="flex items-center space-x-2 bg-dark-800/50 backdrop-blur-sm px-4 py-2 rounded-full border border-dark-700/50"
            >
              <feature.icon className="w-5 h-5 text-cyber-400" />
              <span className="text-gray-300 font-medium">{feature.text}</span>
            </div>
          ))}
        </motion.div>

        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.8, delay: 0.4 }}
          className="flex flex-col sm:flex-row gap-4 justify-center"
        >
          <a
            href="#tools"
            className="cyber-button text-lg px-8 py-3 inline-flex items-center justify-center"
          >
            Comenzar Análisis
          </a>
          
          <a
            href="#docs"
            className="bg-transparent border-2 border-cyber-500/50 text-cyber-400 hover:bg-cyber-500/10 
                     font-medium py-3 px-8 rounded-lg transition-all duration-200 text-lg
                     inline-flex items-center justify-center"
          >
            Documentación
          </a>
        </motion.div>

        {/* Stats */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.8, delay: 0.6 }}
          className="mt-20 grid grid-cols-2 md:grid-cols-4 gap-8"
        >
          {[
            { number: '15+', label: 'Herramientas' },
            { number: '99.9%', label: 'Precisión' },
            { number: '24/7', label: 'Disponibilidad' },
            { number: '∞', label: 'Análisis' },
          ].map((stat, index) => (
            <div key={index} className="text-center">
              <div className="text-3xl font-bold text-cyber-400 mb-2">{stat.number}</div>
              <div className="text-gray-400">{stat.label}</div>
            </div>
          ))}
        </motion.div>
      </div>
    </section>
  );
};

export default Hero;