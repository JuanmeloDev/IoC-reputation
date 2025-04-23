"""# Imports"""

import re
import requests
import pandas as pd
import time
import os
from concurrent.futures import ThreadPoolExecutor

"""# Definicion de constantes"""

API_KEY = "74e84d0144844470390436dd58be2a2737fb10729bfd353d0c1ca97a46b3256b"  # Reemplaza con tu API key
INPUT_FILE = "indicadores.txt"  # Archivo con los IOCs a analizar
OUTPUT_FILE = "resultados_iocs.xlsx"  # Archivo de salida con los resultados
MAX_THREADS = 5  # Número máximo de hilos para procesamiento paralelo

"""# Aplicativo"""

class IOCAnalyzer:
    def __init__(self, api_key, max_threads=5):
        """
        Inicializa el analizador de IOCs.

        Args:
            api_key (str): API key de VirusTotal
            max_threads (int): Máximo número de hilos para procesamiento paralelo
        """
        self.api_key = api_key
        self.max_threads = max_threads
        self.headers = {
            "x-apikey": self.api_key,
            "Accept": "application/json"
        }

    def classify_ioc(self, ioc):
        """
        Clasifica un indicador de compromiso según su tipo.

        Args:
            ioc (str): El indicador a clasificar

        Returns:
            str: El tipo del indicador (hash, ip, domain, url)
        """
        ioc = ioc.strip()

        # Patrones para cada tipo de IOC
        patterns = {
            'md5': r'^[a-fA-F0-9]{32}$',
            'sha1': r'^[a-fA-F0-9]{40}$',
            'sha256': r'^[a-fA-F0-9]{64}$',
            'ip': r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$',
            'url': r'^(https?:\/\/)(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*)$',
            'domain': r'^(?!https?:\/\/)([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        }

        for ioc_type, pattern in patterns.items():
            if re.match(pattern, ioc):
                # Agrupamos los tipos de hash
                if ioc_type in ['md5', 'sha1', 'sha256']:
                    return 'hash'
                return ioc_type

        return 'unknown'

    def get_reputation_from_vt(self, ioc, ioc_type):
        """
        Obtiene la reputación del IOC desde VirusTotal.

        Args:
            ioc (str): El indicador a consultar
            ioc_type (str): El tipo del indicador

        Returns:
            dict: Información sobre la reputación del indicador
        """
        base_url = "https://www.virustotal.com/api/v3/"

        try:
            # Diferentes endpoints según el tipo de IOC
            if ioc_type == 'hash':
                url = f"{base_url}files/{ioc}"
            elif ioc_type == 'ip':
                url = f"{base_url}ip_addresses/{ioc}"
            elif ioc_type == 'domain':
                url = f"{base_url}domains/{ioc}"
            elif ioc_type == 'url':
                # VirusTotal requiere que las URLs estén codificadas en base64
                import base64
                url_id = base64.urlsafe_b64encode(ioc.encode()).decode().strip("=")
                url = f"{base_url}urls/{url_id}"
            else:
                return {"error": "Tipo de IOC desconocido"}

            response = requests.get(url, headers=self.headers)

            if response.status_code == 200:
                data = response.json()

                # Extraer la información relevante según el tipo de IOC
                if 'data' in data:
                    attributes = data['data'].get('attributes', {})

                    result = {
                        'ioc': ioc,
                        'type': ioc_type,
                        'last_analysis_date': attributes.get('last_analysis_date', 'N/A'),
                        'positive_engines': 0,
                        'total_engines': 0,
                        'score': 0
                    }

                    # Obtener resultados de análisis
                    if 'last_analysis_stats' in attributes:
                        stats = attributes['last_analysis_stats']
                        result['positive_engines'] = stats.get('malicious', 0) + stats.get('suspicious', 0)
                        result['total_engines'] = sum(stats.values())
                        if result['total_engines'] > 0:
                            result['score'] = round((result['positive_engines'] / result['total_engines']) * 100, 2)

                    return result
                else:
                    return {"error": "No se encontraron datos"}

            elif response.status_code == 404:
                return {
                    'ioc': ioc,
                    'type': ioc_type,
                    'last_analysis_date': 'N/A',
                    'positive_engines': 0,
                    'total_engines': 0,
                    'score': 0,
                    'error': 'No encontrado en VirusTotal'
                }
            elif response.status_code == 429:
                # Límite de tasa excedido
                print(f"Límite de tasa excedido para {ioc}. Esperando 15 segundos...")
                time.sleep(15)  # Esperar y volver a intentar
                return self.get_reputation_from_vt(ioc, ioc_type)
            else:
                return {
                    'ioc': ioc,
                    'type': ioc_type,
                    'error': f"Error al consultar VirusTotal: {response.status_code}"
                }

        except Exception as e:
            return {
                'ioc': ioc,
                'type': ioc_type,
                'error': f"Error: {str(e)}"
            }

    def process_ioc(self, ioc):
        """
        Procesa un IOC clasificándolo y obteniendo su reputación.

        Args:
            ioc (str): El indicador a procesar

        Returns:
            dict: Resultado del análisis
        """
        ioc = ioc.strip()
        if not ioc or ioc.startswith('#'):
            return None

        ioc_type = self.classify_ioc(ioc)
        if ioc_type == 'unknown':
            return {
                'ioc': ioc,
                'type': 'unknown',
                'error': 'Tipo de IOC no reconocido'
            }

        print(f"Analizando {ioc} (tipo: {ioc_type})...")
        return self.get_reputation_from_vt(ioc, ioc_type)

    def analyze_file(self, file_path):
        """
        Analiza un archivo de texto con IOCs.

        Args:
            file_path (str): Ruta al archivo de IOCs

        Returns:
            pd.DataFrame: DataFrame con los resultados
        """
        if not os.path.exists(file_path):
            print(f"Error: El archivo {file_path} no existe.")
            return pd.DataFrame()

        # Leer el archivo de IOCs
        with open(file_path, 'r') as f:
            iocs = [line.strip() for line in f if line.strip() and not line.startswith('#')]

        print(f"Analizando {len(iocs)} indicadores de compromiso...")

        # Procesar los IOCs en paralelo
        results = []
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            for result in executor.map(self.process_ioc, iocs):
                if result:
                    results.append(result)

        # Crear DataFrame
        df = pd.DataFrame(results)

        # Formatear la fecha de análisis si está disponible
        if not df.empty and 'last_analysis_date' in df.columns:
    # Primero aseguramos que la columna sea de tipo object (string)
          df['last_analysis_date'] = df['last_analysis_date'].astype(str)

          def format_date(x):
            try:
              if x != 'N/A' and x != 'None' and x.isdigit():
                timestamp = int(float(x))
                return time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(timestamp))
              return 'N/A'
            except Exception as e:
              print(f"Error al formatear fecha: {x}, Error: {e}")
              return 'N/A'

        df['last_analysis_date'] = df['last_analysis_date'].apply(format_date)

        return df

    def save_results(self, df, output_file):
      """
      Guarda los resultados en un archivo Excel.

      Args:
        df (pd.DataFrame): DataFrame con los resultados
        output_file (str): Ruta al archivo de salida
      """
      # Aseguramos que el archivo tenga extensión .xlsx
      if not output_file.endswith('.xlsx'):
        output_file = output_file.split('.')[0] + '.xlsx'

      # Guardamos a Excel
      df.to_excel(output_file, index=False, sheet_name='IOCs_Analysis')
      print(f"Resultados guardados en {output_file}")

def main():
    print("Iniciando análisis de indicadores de compromiso...")

    # Usar las constantes definidas al principio del archivo
    analyzer = IOCAnalyzer(API_KEY, MAX_THREADS)
    results_df = analyzer.analyze_file(INPUT_FILE)

    if not results_df.empty:
        # Ordenar por tipo y puntuación
        if 'score' in results_df.columns:
            results_df = results_df.sort_values(['type', 'score'], ascending=[True, False])

        # Mostrar resultados
        pd.set_option('display.max_rows', None)
        pd.set_option('display.max_colwidth', None)
        print("\nResultados del análisis:")
        print(results_df.to_string(index=False))

        # Guardar en Excel
        analyzer.save_results(results_df, OUTPUT_FILE)

        # Mostrar estadísticas
        print("\nEstadísticas por tipo de IOC:")
        print(results_df['type'].value_counts())

        if 'score' in results_df.columns:
            print("\nDetecciones por tipo de IOC:")
            detection_stats = results_df.groupby('type')['score'].agg(['mean', 'min', 'max'])
            print(detection_stats)
        # Importar bibliotecas de visualización
        import matplotlib.pyplot as plt
        import seaborn as sns

        # Configuración para mejorar el aspecto visual
        plt.style.use('ggplot')
        sns.set(font_scale=1.2)

        # Visualización 1: Distribución de IOCs por tipo
        plt.figure(figsize=(10, 6))
        tipo_counts = results_df['type'].value_counts()
        sns.barplot(x=tipo_counts.index, y=tipo_counts.values, palette='viridis')
        plt.title('Distribución de Indicadores por Tipo')
        plt.xlabel('Tipo de IOC')
        plt.ylabel('Cantidad')
        for i, v in enumerate(tipo_counts.values):
          plt.text(i, v + 0.1, str(v), ha='center')
        plt.tight_layout()
        plt.show()
    else:
        print("No se encontraron resultados o hubo un error procesando el archivo.")

if __name__ == "__main__":
    main()