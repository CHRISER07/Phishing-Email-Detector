import streamlit as st
import requests
from urllib.parse import urlparse, quote
from mimetypes import guess_type
import validators
from bs4 import BeautifulSoup

@st.cache_data(ttl=3600)
def get_content_type_cached(url: str) -> tuple:
    """
    Cached function to determine content type using URL and headers
    """
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        
        mime_type, _ = guess_type(url)
        
        if not mime_type:
            response = requests.head(url, headers=headers, timeout=5, allow_redirects=True)
            mime_type = response.headers.get('Content-Type', '').split(';')[0]
            return mime_type.lower() if mime_type else None, dict(response.headers)
        
        return mime_type.lower(), {}
        
    except Exception:
        return None, {}

def display_pdf_preview(url: str):
    """
    Display PDF preview using multiple viewer options
    """
    # Create tabs for different PDF viewing options
    preview_tabs = st.tabs(["Built-in Viewer", "Google Docs Viewer", "PDF.js Viewer"])
    
    with preview_tabs[0]:
        # Built-in browser PDF viewer
        iframe_html = f"""
            <div style="width: 100%; height: 800px; border: 1px solid #ddd; border-radius: 10px; overflow: hidden;">
                <iframe 
                    src="{url}"
                    style="width: 100%; height: 100%; border: none;"
                    type="application/pdf"
                ></iframe>
            </div>
        """
        st.markdown(iframe_html, unsafe_allow_html=True)
    
    with preview_tabs[1]:
        # Google Docs viewer
        encoded_url = quote(url, safe='')
        google_viewer_url = f"https://docs.google.com/viewer?url={encoded_url}&embedded=true"
        iframe_html = f"""
            <div style="width: 100%; height: 800px; border: 1px solid #ddd; border-radius: 10px; overflow: hidden;">
                <iframe 
                    src="{google_viewer_url}"
                    style="width: 100%; height: 100%; border: none;"
                ></iframe>
            </div>
        """
        st.markdown(iframe_html, unsafe_allow_html=True)
    
    with preview_tabs[2]:
        # PDF.js viewer
        pdfjs_url = f"https://mozilla.github.io/pdf.js/web/viewer.html?file={quote(url, safe='')}"
        iframe_html = f"""
            <div style="width: 100%; height: 800px; border: 1px solid #ddd; border-radius: 10px; overflow: hidden;">
                <iframe 
                    src="{pdfjs_url}"
                    style="width: 100%; height: 100%; border: none;"
                ></iframe>
            </div>
        """
        st.markdown(iframe_html, unsafe_allow_html=True)

def display_content(url: str, content_type: str):
    """
    Display content based on its type
    """
    try:
        if content_type and "pdf" in content_type:
            display_pdf_preview(url)
            st.info("If one viewer doesn't work, try switching to another tab.")
        
        elif content_type and "html" in content_type:
            iframe_html = f"""
                <div style="width: 100%; height: 800px; border: 1px solid #ddd; border-radius: 10px; overflow: hidden;">
                    <iframe 
                        src="{url}"
                        style="width: 100%; height: 100%; border: none;"
                        sandbox="allow-same-origin allow-scripts allow-forms"
                        loading="lazy"
                    ></iframe>
                </div>
            """
            st.markdown(iframe_html, unsafe_allow_html=True)
            st.info("Note: Some websites may block embedding in iframes for security reasons.")
        
        elif content_type and "image" in content_type:
            st.image(url, use_column_width=True)
        
        elif content_type and "video" in content_type:
            st.video(url)
        
        elif content_type and "audio" in content_type:
            st.audio(url)
        
        elif content_type and any(t in content_type for t in ["json", "text", "csv"]):
            response = requests.get(url, timeout=5)
            st.code(response.text)
        
        else:
            st.warning(f"Preview not available for content type: {content_type}")
            st.markdown(f"[Open URL directly]({url})")
            
    except Exception as e:
        st.error(f"Error displaying content: {str(e)}")

def main():
    st.set_page_config(
        page_title="Universal Link Viewer",
        page_icon="🔗",
        layout="wide",
        initial_sidebar_state="collapsed"
    )
    
    st.title("Universal Link Viewer 🔗")
    
    st.markdown("Enter any URL to view websites, PDFs, images, videos, or other content.")
    
    url = st.text_input("Enter URL:", placeholder="https://example.com")
    
    if url:
        if not validators.url(url):
            st.error("Please enter a valid URL")
            return
        
        content_type, headers = get_content_type_cached(url)
        
        if content_type:
            # Check for subscription-based academic sites
            academic_domains = ['ieee.org', 'sciencedirect.com', 'springer.com', 'acm.org']
            if any(domain in url.lower() for domain in academic_domains):
                st.warning("⚠️ This appears to be a subscription-based academic paper. You may need to:")
                st.markdown("""
                - Log in through your institution first
                - Check for a free version on Google Scholar or arXiv
                - Contact the authors directly
                """)
                st.markdown(f"[Open in New Tab]({url})")
                return
            
            tabs = st.tabs(["Preview", "Info"])
            
            with tabs[0]:
                display_content(url, content_type)
            
            with tabs[1]:
                st.json({
                    "URL": url,
                    "Content Type": content_type,
                    "Headers": headers
                })

if __name__ == "__main__":
    main()