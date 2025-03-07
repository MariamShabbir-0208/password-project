import streamlit as st
import re
import time
import secrets
import string

# Set page configuration
st.set_page_config(page_title="Password Strength Analyzer", layout="wide")

# Custom CSS with enhanced styling and animations
st.markdown("""
<style>
    .main {
        background: linear-gradient(135deg, #f0f8ff, #e6f0fa);
        padding: 20px;
        border-radius: 15px;
        box-shadow: 0 6px 12px rgba(0, 0, 0, 0.15);
    }
    .stTitle {
        color: #1e3d59;
        text-align: center;
        font-family: 'Arial', sans-serif;
        font-size: 2.5em;
        text-shadow: 1px 1px 2px rgba(0, 0, 0, 0.1);
    }
    .stButton>button {
        background: linear-gradient(45deg, #1e3d59, #2a5d8a);
        color: white;
        border-radius: 8px;
        font-weight: bold;
    }
    .stButton>button:hover {
        background: linear-gradient(45deg, #2a5d8a, #3b7cb8);
    }
    .balloon-pop {
        font-size: 2em;
        animation: pop 0.5s ease infinite;
    }
    .sad-emoji {
        font-size: 1.5em;
        animation: shake 0.5s ease infinite;
    }
    @keyframes pop {
        0% { transform: scale(1); }
        50% { transform: scale(1.2); }
        100% { transform: scale(1); }
    }
    @keyframes shake {
        0% { transform: translateX(0); }
        25% { transform: translateX(-5px); }
        75% { transform: translateX(5px); }
        100% { transform: translateX(0); }
    }
    .slider {
        background: linear-gradient(90deg, #ff6b6b, #4ecdc4, #45b7d1);
        padding: 20px;
        border-radius: 10px;
        text-align: center;
        color: white;
        font-size: 1.2em;
        margin-bottom: 20px;
    }
</style>
""", unsafe_allow_html=True)

# Password strength function (unchanged from previous)
def password_strength(password):
    score = 0
    feedback = []

    length = len(password)
    if length >= 16:
        score += 3
    elif length >= 12:
        score += 2
    elif length >= 8:
        score += 1
    else:
        feedback.append("🔍 Password should be at least 8 characters (12+ recommended, 16+ ideal).")

    if re.search(r'[A-Z]', password):
        score += 1
    else:
        feedback.append("🔤 Include at least one uppercase letter.")
    if re.search(r'[a-z]', password):
        score += 1
    else:
        feedback.append("🔤 Include at least one lowercase letter.")

    digits = len(re.findall(r'\d', password))
    if digits >= 3:
        score += 2
    elif digits >= 1:
        score += 1
    else:
        feedback.append("🔢 Include at least one number (3+ for extra strength).")

    special_chars = r'[!@#$%^&*(),.?":{}|<>]'
    special_count = len(re.findall(special_chars, password))
    if special_count >= 3:
        score += 2
    elif special_count >= 1:
        score += 1
    else:
        feedback.append("🔣 Include at least one special character (3+ for extra strength).")

    unique_chars = len(set(password))
    if unique_chars >= 12:
        score += 1
    elif unique_chars < length // 2:
        feedback.append("🔄 Avoid repeating characters too much.")

    common_patterns = ["123", "abc", "qwerty", "password", "admin", "letmein"]
    if any(pattern in password.lower() for pattern in common_patterns):
        score -= 2
        feedback.append("⚠️ Avoid common patterns or dictionary words.")

    if score <= 3:
        strength = "Weak"
        color = "red"
    elif score <= 6:
        strength = "Moderate"
        color = "orange"
    elif score <= 9:
        strength = "Strong"
        color = "blue"
    else:
        strength = "Very Strong"
        color = "green"

    return strength, feedback, color, score

# Password generator
def generate_secure_password(length=16):
    alphabet = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(alphabet) for _ in range(length))

def main():
    # Homepage slider (rotating messages)
    slider_messages = [
        "🔒 Build unbreakable passwords with ease!",
        "🎉 Strong passwords = Happy security!",
        "💡 Get tips and generate secure passwords now!"
    ]
    if 'slider_index' not in st.session_state:
        st.session_state.slider_index = 0
    st.markdown(f"<div class='slider'>{slider_messages[st.session_state.slider_index]}</div>", unsafe_allow_html=True)
    # Auto-rotate slider every 3 seconds
    time.sleep(3)
    st.session_state.slider_index = (st.session_state.slider_index + 1) % len(slider_messages)

    st.title("🔐 Password Strength Analyzer")
    st.markdown("<div style='text-align: center; color: #555;'>Evaluate or generate a password with style!</div>", unsafe_allow_html=True)

    # Track previous password for duplicate detection
    if 'prev_password' not in st.session_state:
        st.session_state.prev_password = None

    # Tabs for navigation
    tab1, tab2 = st.tabs(["Analyze Password", "Generate Password"])

    with tab1:
        col1, col2 = st.columns([3, 1])
        with col1:
            password = st.text_input("Enter your password:", type="password", key="analyze_input")
        with col2:
            show_password = st.checkbox("Show password")
            if show_password and password:
                st.text(password)

        if st.button("Analyze Password", type="primary", key="analyze_button"):
            if password:
                with st.spinner("Analyzing password..."):
                    time.sleep(0.5)
                    strength, feedback, color, score = password_strength(password)

                    # Check for duplicate password
                    if password == st.session_state.prev_password:
                        st.markdown("<div class='sad-emoji'>😞</div>", unsafe_allow_html=True)
                        st.warning("You've used this password before. Try something new!")
                    else:
                        st.session_state.prev_password = password

                    # Strength display with celebration
                    st.markdown(f"### Password Strength: <span style='color:{color}'>{strength}</span> {'⭐' * min(score // 3, 4)}", unsafe_allow_html=True)
                    st.progress(min(score / 12, 1.0))
                    st.caption(f"Score: {score}/12")

                    if strength == "Very Strong":
                        st.markdown("<div class='balloon-pop'>🎈🎉🎈</div>", unsafe_allow_html=True)
                        st.success("Boom! Your password is a security superstar!")
                    elif strength == "Weak":
                        st.markdown("<div class='sad-emoji'>😢</div>", unsafe_allow_html=True)
                        st.error("Uh-oh! This password needs some love.")

                    if feedback:
                        st.subheader("Suggestions for Improvement:")
                        for item in feedback:
                            st.warning(item)

                    # Stats
                    st.subheader("Password Breakdown:")
                    col1, col2, col3, col4 = st.columns(4)
                    with col1:
                        st.info(f"Length: {len(password)}")
                    with col2:
                        st.info(f"Numbers: {len(re.findall(r'\d', password))}")
                    with col3:
                        st.info(f"Special: {len(re.findall(r'[!@#$%^&*(),.?\":{}|<>]', password))}")
                    with col4:
                        st.info(f"Unique: {len(set(password))}")
            else:
                st.error("Please enter a password to analyze.")

    with tab2:
        st.subheader("Generate a Secure Password")
        length = st.slider("Password Length", 8, 32, 16)
        if st.button("Generate Password", key="generate_button"):
            new_password = generate_secure_password(length)
            st.code(new_password, language="text")
            strength, _, color, score = password_strength(new_password)
            st.markdown(f"Generated Password Strength: <span style='color:{color}'>{strength}</span>", unsafe_allow_html=True)
            if strength == "Very Strong":
                st.markdown("<div class='balloon-pop'>🎈🎉🎈</div>", unsafe_allow_html=True)
                st.success("Pop! A super-strong password has been generated!")
            st.info("Copy this password and test it in the 'Analyze Password' tab!")

    # Tips section
    with st.expander("📌 Tips for a Strong Password", expanded=False):
        st.markdown("""
        - **Length**: Aim for 12+ characters (16+ is ideal).
        - **Variety**: Mix uppercase, lowercase, numbers, and special characters.
        - **Uniqueness**: Avoid personal info (e.g., name, birthdate).
        - **Randomness**: Don’t use predictable patterns (e.g., "1234", "qwerty").
        - **Diversity**: Use unique passwords for each account.
        - **Storage**: Consider a password manager for secure storage.
        """)

if __name__ == "__main__":
    main()