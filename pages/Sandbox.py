import streamlit as st
import requests
from urllib.parse import urlparse
from mimetypes import guess_type
import validators
from bs4 import BeautifulSoup
import tempfile
import os

def get_content_type(url: str, headers: dict) -> str:
    """
    Determine content type using URL and response headers
    """
    # First try mime type from URL
    mime_type, _ = guess_type(url)
    
    if mime_type is None:
        # Use Content-Type header as fallback
        mime_type = headers.get('Content-Type', '').split(';')[0]
    
    return mime_type.lower() if mime_type else None

def get_webpage_metadata(content: bytes) -> dict:
    """
    Extract metadata from webpage
    """
    soup = BeautifulSoup(content, 'html.parser')
    
    return {
        'title': soup.title.string if soup.title else None,
        'description': soup.find('meta', {'name': 'description'})['content'] if soup.find('meta', {'name': 'description'}) else None,
        'favicon': soup.find('link', rel='icon')['href'] if soup.find('link', rel='icon') else None
    }

def fetch_and_display_url(url: str):
    """
    Fetch and display content from a given URL based on its type.
    Handles multiple content types including PDF, HTML, images, videos, and more.
    """
    try:
        # Validate URL
        if not validators.url(url):
            st.error("Please enter a valid URL")
            return
        
        # Fetch content with proper headers
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        
        with st.spinner("Fetching content..."):
            # First make a HEAD request to get content type
            head_response = requests.head(url, headers=headers, allow_redirects=True)
            content_type = get_content_type(url, head_response.headers)
            
            if content_type:
                st.success(f"Detected content type: {content_type}")
            
            # Create tabs for preview and details
            preview_tab, details_tab = st.tabs(["Preview", "Details"])
            
            with preview_tab:
                # Handle different content types
                if content_type and "pdf" in content_type:
                    # Fetch and display PDF
                    response = requests.get(url, headers=headers)
                    with tempfile.NamedTemporaryFile(delete=False, suffix='.pdf') as tmp_file:
                        tmp_file.write(response.content)
                        tmp_file.flush()
                        st.pdf(tmp_file.name)
                        os.unlink(tmp_file.name)  # Clean up temp file
                
                elif content_type and "html" in content_type:
                    # Show website preview in iframe
                    st.write("Website Preview:")
                    iframe_html = f"""
                        <div style="width: 100%; height: 800px; border: 1px solid #ddd; border-radius: 10px; overflow: hidden;">
                            <iframe 
                                src="{url}"
                                style="width: 100%; height: 100%; border: none;"
                                sandbox="allow-same-origin allow-scripts allow-forms"
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
                    response = requests.get(url, headers=headers)
                    st.code(response.text)
                
                else:
                    st.warning(f"Preview not available for content type: {content_type}")
                    st.markdown(f"[Open URL directly]({url})")
            
            with details_tab:
                # Get full response for metadata
                response = requests.get(url, headers=headers)
                
                details = {
                    "url": url,
                    "content_type": content_type,
                    "size": len(response.content),
                    "status_code": response.status_code,
                    "encoding": response.encoding,
                    "headers": dict(response.headers)
                }
                
                if content_type and "html" in content_type:
                    details["metadata"] = get_webpage_metadata(response.content)
                
                st.json(details)

    except requests.exceptions.SSLError:
        st.error("SSL Certificate verification failed. The website might be unsafe.")
    except requests.exceptions.ConnectionError:
        st.error("Failed to connect to the server. Please check the URL and try again.")
    except requests.exceptions.Timeout:
        st.error("Request timed out. The server took too long to respond.")
    except requests.exceptions.RequestException as e:
        st.error(f"Error fetching content: {str(e)}")
    except Exception as e:
        st.error(f"Unexpected error: {str(e)}")

def main():
    st.set_page_config(page_title="Universal Link Viewer", page_icon="🔗", layout="wide")
    
    st.title("Universal Link Viewer 🔗")
    st.markdown("""
    Enter any URL to view its content directly in the app. Supports:
    - Websites (HTML)
    - PDF documents
    - Images (JPG, PNG, GIF, etc.)
    - Videos (MP4, etc.)
    - Audio files
    - Text files (JSON, CSV, TXT)
    """)
    
    # URL input with example
    url = st.text_input(
        "Enter URL:",
        placeholder="https://example.com/document.pdf",
        help="Enter the URL of any supported content type"
    )
    
    if url:
        fetch_and_display_url(url)

if __name__ == "__main__":
    main()
