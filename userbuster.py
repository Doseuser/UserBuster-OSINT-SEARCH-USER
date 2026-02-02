#!/usr/bin/env python3
"""
OSINT UserFinder - Herramienta avanzada de búsqueda de usuarios en plataformas
Características:
- Verificación robusta para evitar falsos positivos
- Múltiples métodos de validación
- Async/await para alta velocidad
- Exportación en múltiples formatos
- Configuración modular
"""

import asyncio
import aiohttp
import json
import re
import time
from urllib.parse import urljoin
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Tuple
from enum import Enum
from colorama import init, Fore, Style
import argparse
import sys
import yaml
from datetime import datetime
import logging

# Configuración de logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Inicializar colorama para colores en consola
init(autoreset=True)

class VerificationLevel(Enum):
    """Niveles de verificación para resultados"""
    HIGH = "high"      # Múltiples métodos de confirmación
    MEDIUM = "medium"  # Algunos indicadores positivos
    LOW = "low"        # Posible match
    NONE = "none"      # No verificado

@dataclass
class UserProfile:
    """Estructura para perfiles de usuario encontrados"""
    username: str
    platform: str
    url: str
    exists: bool
    verification_level: VerificationLevel
    confidence: float
    additional_info: Dict
    response_time: float
    timestamp: str

class PlatformScanner:
    """Escáner para plataformas específicas"""
    
    def __init__(self, platform_name: str, base_url: str, patterns: Dict):
        self.name = platform_name
        self.base_url = base_url
        self.patterns = patterns
        self.session = None
        
    async def initialize(self):
        """Inicializar sesión async"""
        timeout = aiohttp.ClientTimeout(total=10)
        self.session = aiohttp.ClientSession(timeout=timeout)
    
    async def close(self):
        """Cerrar sesión"""
        if self.session:
            await self.session.close()
    
    async def verify_user(self, username: str) -> UserProfile:
        """Verificar usuario con múltiples métodos"""
        start_time = time.time()
        
        try:
            # Método 1: Verificación directa de página
            profile_url = urljoin(self.base_url, self.patterns.get("profile_url", "").format(username=username))
            
            async with self.session.get(profile_url, allow_redirects=False) as response:
                status = response.status
                
                # Verificar códigos de estado
                if status == 404:
                    return self._create_profile(username, False, VerificationLevel.HIGH, 0.0, start_time)
                
                if status in [200, 302, 301]:
                    # Método 2: Análisis de contenido
                    content = await response.text()
                    
                    # Verificaciones múltiples
                    checks = self._perform_content_checks(username, content, response)
                    
                    # Calcular confianza
                    confidence = self._calculate_confidence(checks)
                    
                    if confidence > 0.7:
                        verification = VerificationLevel.HIGH
                    elif confidence > 0.4:
                        verification = VerificationLevel.MEDIUM
                    else:
                        verification = VerificationLevel.LOW
                    
                    return self._create_profile(
                        username, 
                        True, 
                        verification, 
                        confidence, 
                        start_time,
                        additional_info=checks,
                        url=profile_url
                    )
            
            return self._create_profile(username, False, VerificationLevel.HIGH, 0.0, start_time)
            
        except Exception as e:
            logger.error(f"Error scanning {self.name}: {e}")
            return self._create_profile(username, False, VerificationLevel.NONE, 0.0, start_time)
    
    def _perform_content_checks(self, username: str, content: str, response) -> Dict:
        """Realizar múltiples verificaciones de contenido"""
        checks = {}
        
        # Check 1: Presencia del username en el contenido
        checks['username_in_content'] = username.lower() in content.lower()
        
        # Check 2: Patrones específicos de la plataforma
        if "patterns" in self.patterns:
            for pattern_name, pattern in self.patterns["patterns"].items():
                if re.search(pattern, content, re.IGNORECASE):
                    checks[f'pattern_{pattern_name}'] = True
        
        # Check 3: Headers específicos
        checks['has_user_headers'] = any(
            'user' in key.lower() for key in response.headers.keys()
        )
        
        # Check 4: Tamaño de contenido (páginas de error suelen ser más pequeñas)
        checks['sufficient_content_length'] = len(content) > 1000
        
        # Check 5: URLs en la página
        checks['has_profile_links'] = f"/{username}" in content or f"@{username}" in content
        
        return checks
    
    def _calculate_confidence(self, checks: Dict) -> float:
        """Calcular nivel de confianza basado en verificaciones"""
        total_checks = len(checks)
        if total_checks == 0:
            return 0.0
        
        positive_checks = sum(1 for check in checks.values() if check)
        return positive_checks / total_checks
    
    def _create_profile(self, username: str, exists: bool, verification: VerificationLevel, 
                       confidence: float, start_time: float, **kwargs) -> UserProfile:
        """Crear objeto UserProfile"""
        return UserProfile(
            username=username,
            platform=self.name,
            exists=exists,
            verification_level=verification,
            confidence=confidence,
            response_time=time.time() - start_time,
            timestamp=datetime.now().isoformat(),
            **kwargs
        )

class UserFinder:
    """Clase principal para búsqueda de usuarios"""
    
    def __init__(self, config_file: str = "platforms.yaml"):
        self.platforms = {}
        self.results = []
        self.load_platforms(config_file)
    
    def load_platforms(self, config_file: str):
        """Cargar configuración de plataformas desde YAML"""
        try:
            with open(config_file, 'r', encoding='utf-8') as f:
                config = yaml.safe_load(f)
            
            for platform_name, platform_config in config.get("platforms", {}).items():
                self.platforms[platform_name] = PlatformScanner(
                    platform_name,
                    platform_config["base_url"],
                    platform_config
                )
            
            logger.info(f"Cargadas {len(self.platforms)} plataformas")
            
        except FileNotFoundError:
            logger.error(f"Archivo de configuración no encontrado: {config_file}")
            sys.exit(1)
        except yaml.YAMLError as e:
            logger.error(f"Error en archivo YAML: {e}")
            sys.exit(1)
    
    async def search_user(self, username: str, max_concurrent: int = 20) -> List[UserProfile]:
        """Buscar usuario en todas las plataformas"""
        logger.info(f"Iniciando búsqueda para usuario: {username}")
        
        # Inicializar scanners
        tasks = []
        scanners = list(self.platforms.values())
        
        for scanner in scanners:
            await scanner.initialize()
        
        # Crear tareas async
        semaphore = asyncio.Semaphore(max_concurrent)
        
        async def limited_scan(scanner):
            async with semaphore:
                return await scanner.verify_user(username)
        
        tasks = [limited_scan(scanner) for scanner in scanners]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Procesar resultados
        valid_results = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                logger.error(f"Error en {scanners[i].name}: {result}")
                continue
            if result and result.exists:
                valid_results.append(result)
        
        # Cerrar sesiones
        for scanner in scanners:
            await scanner.close()
        
        self.results = valid_results
        return valid_results
    
    def print_results(self, show_all: bool = False):
        """Mostrar resultados en formato legible"""
        print(f"\n{Fore.CYAN}{Style.BRIGHT}=== RESULTADOS DE BÚSQUEDA ==={Style.RESET_ALL}\n")
        
        found_count = len([r for r in self.results if r.exists and r.verification_level != VerificationLevel.NONE])
        print(f"Usuarios encontrados: {Fore.GREEN}{found_count}{Style.RESET_ALL}")
        
        # Agrupar por nivel de verificación
        high_confidence = []
        medium_confidence = []
        low_confidence = []
        
        for result in self.results:
            if not result.exists or result.verification_level == VerificationLevel.NONE:
                continue
                
            if result.verification_level == VerificationLevel.HIGH:
                high_confidence.append(result)
            elif result.verification_level == VerificationLevel.MEDIUM:
                medium_confidence.append(result)
            else:
                low_confidence.append(result)
        
        # Mostrar resultados de alta confianza
        if high_confidence:
            print(f"\n{Fore.GREEN}✓ ALTA CONFIANZA ({len(high_confidence)}){Style.RESET_ALL}")
            for result in high_confidence:
                print(f"  • {Fore.GREEN}{result.platform:<20}{Style.RESET_ALL} {result.url}")
                if show_all:
                    print(f"    Confianza: {result.confidence:.1%} | Tiempo: {result.response_time:.2f}s")
        
        # Mostrar resultados de confianza media
        if medium_confidence:
            print(f"\n{Fore.YELLOW}⚠ CONFIANZA MEDIA ({len(medium_confidence)}){Style.RESET_ALL}")
            for result in medium_confidence:
                print(f"  • {Fore.YELLOW}{result.platform:<20}{Style.RESET_ALL} {result.url}")
        
        # Mostrar resultados de baja confianza
        if low_confidence:
            print(f"\n{Fore.RED}? BAJA CONFIANZA ({len(low_confidence)}){Style.RESET_ALL}")
            for result in low_confidence:
                print(f"  • {Fore.RED}{result.platform:<20}{Style.RESET_ALL} {result.url}")
    
    def export_results(self, username: str, formats: List[str] = ["json", "txt"]):
        """Exportar resultados a diferentes formatos"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_filename = f"results/{username}_{timestamp}"
        
        os.makedirs("results", exist_ok=True)
        
        data = {
            "username": username,
            "timestamp": datetime.now().isoformat(),
            "total_found": len([r for r in self.results if r.exists]),
            "results": [asdict(r) for r in self.results if r.exists]
        }
        
        for format_type in formats:
            if format_type == "json":
                filename = f"{base_filename}.json"
                with open(filename, 'w', encoding='utf-8') as f:
                    json.dump(data, f, indent=2, ensure_ascii=False)
                logger.info(f"Resultados exportados a {filename}")
            
            elif format_type == "txt":
                filename = f"{base_filename}.txt"
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(f"Resultados para: {username}\n")
                    f.write(f"Fecha: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write(f"Total encontrados: {data['total_found']}\n\n")
                    
                    for result in data["results"]:
                        f.write(f"Plataforma: {result['platform']}\n")
                        f.write(f"URL: {result.get('url', 'N/A')}\n")
                        f.write(f"Confianza: {result['confidence']:.1%}\n")
                        f.write(f"Nivel: {result['verification_level']}\n")
                        f.write("-" * 40 + "\n")
                
                logger.info(f"Resultados exportados a {filename}")

async def main():
    """Función principal"""
    parser = argparse.ArgumentParser(
        description="Herramienta avanzada de búsqueda de usuarios en plataformas",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos:
  %(prog)s johndoe
  %(prog)s johndoe --export json txt
  %(prog)s johndoe --platforms twitter github instagram
  %(prog)s johndoe --verbose --show-all
        """
    )
    
    parser.add_argument("username", help="Nombre de usuario a buscar")
    parser.add_argument("-e", "--export", nargs="+", choices=["json", "txt", "csv"],
                       help="Formatos de exportación")
    parser.add_argument("-p", "--platforms", nargs="+",
                       help="Plataformas específicas a escanear")
    parser.add_argument("-v", "--verbose", action="store_true",
                       help="Mostrar información detallada")
    parser.add_argument("-a", "--show-all", action="store_true",
                       help="Mostrar todos los resultados incluyendo baja confianza")
    parser.add_argument("-c", "--config", default="platforms.yaml",
                       help="Archivo de configuración de plataformas")
    parser.add_argument("-m", "--max-concurrent", type=int, default=20,
                       help="Número máximo de peticiones concurrentes")
    
    args = parser.parse_args()
    
    # Configurar logging verbose
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Crear instancia del buscador
    finder = UserFinder(args.config)
    
    # Filtrar plataformas si se especificó
    if args.platforms:
        filtered_platforms = {}
        for platform in args.platforms:
            if platform in finder.platforms:
                filtered_platforms[platform] = finder.platforms[platform]
            else:
                logger.warning(f"Plataforma no encontrada: {platform}")
        finder.platforms = filtered_platforms
    
    # Realizar búsqueda
    start_time = time.time()
    results = await finder.search_user(args.username, args.max_concurrent)
    search_time = time.time() - start_time
    
    # Mostrar resultados
    finder.print_results(args.show_all)
    
    # Exportar resultados
    if args.export:
        finder.export_results(args.username, args.export)
    
    print(f"\n{Fore.CYAN}Tiempo total de búsqueda: {search_time:.2f} segundos{Style.RESET_ALL}")

if __name__ == "__main__":
    import os
    
    # Crear estructura de directorios
    os.makedirs("results", exist_ok=True)
    os.makedirs("config", exist_ok=True)
    
    # Verificar archivo de configuración
    if not os.path.exists("platforms.yaml"):
        print(f"{Fore.YELLOW}Creando archivo de configuración por defecto...{Style.RESET_ALL}")
        
        default_config = {
            "platforms": {
                "GitHub": {
                    "base_url": "https://github.com/",
                    "profile_url": "{username}",
                    "patterns": {
                        "profile": "class=\"vcard-names\"",
                        "username": "itemprop=\"additionalName\""
                    }
                },
                "Twitter": {
                    "base_url": "https://twitter.com/",
                    "profile_url": "{username}",
                    "patterns": {
                        "username": "data-testid=\"UserName\"",
                        "tweets": "data-testid=\"tweet\""
                    }
                },
                "Instagram": {
                    "base_url": "https://www.instagram.com/",
                    "profile_url": "{username}/",
                    "patterns": {
                        "profile": "property=\"og:description\"",
                        "username": "\"username\""
                    }
                },
                "Reddit": {
                    "base_url": "https://www.reddit.com/user/",
                    "profile_url": "{username}",
                    "patterns": {
                        "profile": "class=\"_3YNtuTmUcBkXWY5jICz5uL\"",
                        "karma": "karma"
                    }
                }
            }
        }
        
        with open("platforms.yaml", "w", encoding='utf-8') as f:
            yaml.dump(default_config, f, default_flow_style=False)
        
        print(f"{Fore.GREEN}Archivo platforms.yaml creado. Edítalo para agregar más plataformas.{Style.RESET_ALL}")
    
    # Ejecutar búsqueda
    asyncio.run(main())
