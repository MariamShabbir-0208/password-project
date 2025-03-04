import streamlit as st
import re
import time

# Set page configuration and styling
st.set_page_config(page_title="Password Strength Analyzer", layout="centered")

# Custom CSS
st.markdown("""
<style>
    .main {
        background-color: #f0f8ff;
        padding: 20px;
        border-radius: 10px;
    }
    .stTitle {
        color: #1e3d59;
        text-align: center;
    }
    .password-input {
        margin: 20px 0;
    }
</style>
""", unsafe_allow_html=True)

def password_strength(password):
    score = 0
    feedback = []

    # Check length with more detailed scoring
    if len(password) >= 12:
        score += 2
    elif len(password) >= 8:
        score += 1
    else:
        feedback.append("🔍 Password should be at least 8 characters long (12+ recommended).")

    # Check for uppercase and lowercase letters
    if re.search(r'[A-Z]', password) and re.search(r'[a-z]', password):
        score += 1
    else:
        feedback.append("🔤 Include both uppercase and lowercase letters.")

    # Check for digits
    if re.search(r'\d{2,}', password):
        score += 2
    elif re.search(r'\d', password):
        score += 1
    else:
        feedback.append("🔢 Include at least one number (0-9).")

    # Check for special characters
    special_chars = r'[!@#$%^&*(),.?":{}|<>]'
    if len(re.findall(special_chars, password)) >= 2:
        score += 2
    elif re.search(special_chars, password):
        score += 1
    else:
        feedback.append("🔣 Include at least one special character (!@#$%^&*).")

    # Check for common patterns
    common_patterns = ["123", "abc", "qwerty", "password", "admin"]
    if any(pattern in password.lower() for pattern in common_patterns):
        score -= 1
        feedback.append("⚠️ Avoid common patterns in your password.")

    # Determine strength and color
    if score <= 2:
        strength = "Weak"
        color = "red"
    elif score <= 4:
        strength = "Moderate"
        color = "orange"
    elif score <= 6:
        strength = "Strong"
        color = "blue"
    else:
        strength = "Very Strong"
        color = "green"

    return strength, feedback, color, score

def main():
    st.title("🔐 Password Strength Analyzer")
    
    # Add description
    st.markdown("""
    Create a strong password that meets security requirements. 
    This tool will help you evaluate your password strength.
    """)

    # Create two columns for layout
    col1, col2 = st.columns([3, 1])

    with col1:
        password = st.text_input("Enter your password:", type="password")
    
    with col2:
        show_password = st.checkbox("Show password")
        if show_password:
            st.text(password)

    if st.button("Analyze Password", type="primary"):
        if password:
            with st.spinner("Analyzing password..."):
                time.sleep(0.5)  # Add a small delay for effect
                strength, feedback, color, score = password_strength(password)
                
                # Display strength with color
                st.markdown(f"### Password Strength: <span style='color:{color}'>{strength}</span>", unsafe_allow_html=True)
                
                # Create a progress bar
                st.progress(score/8)
                
                # Display feedback
                if feedback:
                    st.subheader("Suggestions for improvement:")
                    for item in feedback:
                        st.warning(item)
                elif strength == "Very Strong":
                    st.success("🎉 Excellent! Your password is very strong!")
                
                # Add password statistics
                st.subheader("Password Statistics:")
                col1, col2, col3 = st.columns(3)
                with col1:
                    st.info(f"Length: {len(password)}")
                with col2:
                    st.info(f"Numbers: {len(re.findall(r'\d', password))}")
                with col3:
                    st.info(f"Special chars: {len(re.findall(r'[!@#$%^&*(),.?\":{}|<>]', password))}")
        else:
            st.error("Please enter a password to analyze.")

    # Add tips section
    with st.expander("📌 Tips for a Strong Password"):
        st.markdown("""
        - Use at least 12 characters
        - Mix uppercase and lowercase letters
        - Include numbers and special characters
        - Avoid personal information
        - Don't use common words or patterns
        - Use different passwords for different accounts
        """)

if __name__ == "__main__":
    main()
