"""
BlackBox Recon - Technology Detection Phase
Phase 3: Identify web technologies, frameworks, servers from response patterns
"""
import re
from typing import Dict, Any, List
from app.recon.base import BaseReconPhase


class TechDetectionPhase(BaseReconPhase):
    """Technology Detection reconnaissance phase."""
    
    name = "tech_detection"
    order = 3
    description = "Identify web technologies, frameworks, and servers"
    
    # Technology signatures: (pattern, technology_name, confidence)
    TECH_SIGNATURES = [
        # Server headers
        (r'nginx', 'Nginx', 'high'),
        (r'apache', 'Apache', 'high'),
        (r'iis', 'Microsoft IIS', 'high'),
        (r'openresty', 'OpenResty', 'high'),
        
        # Frameworks
        (r'django', 'Django', 'high'),
        (r'rails', 'Ruby on Rails', 'high'),
        (r'laravel', 'Laravel', 'high'),
        (r'express', 'Express.js', 'medium'),
        (r'flask', 'Flask', 'medium'),
        (r'react', 'React', 'medium'),
        (r'vue\.js', 'Vue.js', 'medium'),
        (r'angular', 'Angular', 'medium'),
        (r'next\.js', 'Next.js', 'medium'),
        (r'nuxt', 'Nuxt.js', 'medium'),
        
        # CMS
        (r'wordpress', 'WordPress', 'high'),
        (r'drupal', 'Drupal', 'high'),
        (r'joomla', 'Joomla', 'high'),
        
        # Programming languages
        (r'php', 'PHP', 'medium'),
        (r'python', 'Python', 'low'),
        (r'ruby', 'Ruby', 'low'),
        
        # Web servers
        (r'tomcat', 'Apache Tomcat', 'high'),
        (r'jetty', 'Jetty', 'high'),
        (r'gunicorn', 'Gunicorn', 'high'),
        (r'uwsgi', 'uWSGI', 'high'),
        
        # CDN/Cloud
        (r'cloudflare', 'Cloudflare', 'high'),
        (r'awselb', 'AWS ELB', 'high'),
        (r'google cloud', 'Google Cloud', 'medium'),
        (r'azure', 'Microsoft Azure', 'medium'),
        
        # Path patterns
        (r'/wp-content/', 'WordPress', 'high'),
        (r'/wp-includes/', 'WordPress', 'high'),
        (r'/sites/default/files/', 'Drupal', 'high'),
        (r'/media/jui/', 'Joomla', 'high'),
        (r'/static/admin/', 'Django Admin', 'high'),
        (r'/_next/static/', 'Next.js', 'high'),
        (r'/nuxt/', 'Nuxt.js', 'medium'),
    ]
    
    async def execute(self) -> Dict[str, Any]:
        """Execute technology detection."""
        try:
            technologies: List[Dict[str, str]] = []
            detected_names = set()
            
            # Analyze HTTP fingerprinting results if available from previous phase
            http_results = self.context.get('http_fingerprinting', {}) if hasattr(self, 'context') else {}
            server_info = http_results.get('server_info', {})
            detailed_results = http_results.get('detailed_results', {})
            
            # Check server header
            if 'server_header' in server_info:
                server = server_info['server_header'].lower()
                for pattern, tech, confidence in self.TECH_SIGNATURES:
                    if re.search(pattern, server, re.IGNORECASE):
                        if tech not in detected_names:
                            technologies.append({
                                "technology": tech,
                                "confidence": confidence,
                                "evidence": f"Server header: {server_info['server_header']}",
                                "source": "server_header"
                            })
                            detected_names.add(tech)
            
            # Check X-Powered-By
            if 'powered_by' in server_info:
                powered_by = server_info['powered_by'].lower()
                for pattern, tech, confidence in self.TECH_SIGNATURES:
                    if re.search(pattern, powered_by, re.IGNORECASE):
                        if tech not in detected_names:
                            technologies.append({
                                "technology": tech,
                                "confidence": confidence,
                                "evidence": f"X-Powered-By: {server_info['powered_by']}",
                                "source": "x_powered_by"
                            })
                            detected_names.add(tech)
            
            # Check detailed response bodies if available
            for method, result in detailed_results.items():
                if isinstance(result, dict) and 'headers' in result:
                    headers = result.get('headers', {})
                    
                    # Check various headers
                    for header_name, header_value in headers.items():
                        for pattern, tech, confidence in self.TECH_SIGNATURES:
                            if re.search(pattern, str(header_value), re.IGNORECASE):
                                if tech not in detected_names:
                                    technologies.append({
                                        "technology": tech,
                                        "confidence": confidence,
                                        "evidence": f"{header_name}: {header_value}",
                                        "source": f"http_header_{header_name.lower()}"
                                    })
                                    detected_names.add(tech)
            
            # Add findings for detected technologies
            for tech in technologies:
                self.add_finding(
                    finding_type="technology_detected",
                    title=f"Technology Detected: {tech['technology']}",
                    severity="info",
                    description=f"Detected {tech['technology']} with {tech['confidence']} confidence",
                    evidence=tech['evidence'],
                    metadata={"technology": tech['technology'], "confidence": tech['confidence'], "source": tech['source']}
                )
            
            return {
                "technologies": technologies,
                "technology_count": len(technologies),
                "status": "completed"
            }
            
        except Exception as e:
            return {
                "technologies": [],
                "technology_count": 0,
                "status": "failed",
                "error": str(e)
            }
