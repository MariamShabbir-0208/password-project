import streamlit as st
import os

if "library" not in st.session_state:
    st.session_state.library = []

def main():
    st.title("📚 Personal Library Manager")
    st.markdown("Welcome to your **colorful** and **fun** book tracker! 🎉", unsafe_allow_html=True)
    
    menu = st.sidebar.selectbox(
        "Choose an Action 📖",
        ["Add a Book", "Remove a Book", "Search for a Book", "Display All Books", "Display Statistics"],
        format_func=lambda x: f"✨ {x}"
    )
    
    if not st.session_state.library:
        load_library()
        if st.session_state.library:
            st.sidebar.info("📂 Library loaded from file!")

    with st.sidebar:
        st.markdown("---")
        if st.button("💾 Save Library"):
            save_library()
            st.success("✅ Library saved successfully!")

    if menu == "Add a Book":
        add_book()
    elif menu == "Remove a Book":
        remove_book()
    elif menu == "Search for a Book":
        search_book()
    elif menu == "Display All Books":
        display_all_books()
    elif menu == "Display Statistics":
        display_statistics()

def add_book():
    st.subheader("📖 Add a New Book")
    st.markdown("Fill in the details below to grow your library! 🌟", unsafe_allow_html=True)
    
    title = st.text_input("📝 Book Title", placeholder="e.g., The Great Gatsby")
    author = st.text_input("✍️ Author", placeholder="e.g., F. Scott Fitzgerald")
    year = st.number_input("📅 Publication Year", min_value=0, max_value=9999, step=1, value=2023)
    genre = st.text_input("🎭 Genre", placeholder="e.g., Fiction")
    read_status = st.checkbox("✅ Have you read this book?")
    
    if st.button("➕ Add Book", key="add"):
        if title and author and genre:
            book = {
                "title": title,
                "author": author,
                "year": int(year),
                "genre": genre,
                "read": read_status
            }
            st.session_state.library.append(book)
            st.success(f"🎉 '{title}' added to your library!")
        else:
            st.warning("⚠️ Please fill in all fields!")

def remove_book():
    st.subheader("🗑️ Remove a Book")
    st.markdown("Enter the title to remove it from your collection. 🚮", unsafe_allow_html=True)
    
    title = st.text_input("📝 Enter the title to remove", placeholder="e.g., The Great Gatsby")
    
    if st.button("❌ Remove Book", key="remove"):
        for book in st.session_state.library[:]:
            if book["title"].lower() == title.lower():
                st.session_state.library.remove(book)
                st.success(f"✅ '{title}' removed from your library!")
                return
        st.error(f"❌ No book with title '{title}' found.")

def search_book():
    st.subheader("🔍 Search for a Book")
    st.markdown("Find your books by title or author! 🕵️‍♂️", unsafe_allow_html=True)
    
    search_term = st.text_input("🔎 Search by title or author", placeholder="Type here...")
    
    if search_term:
        matches = [book for book in st.session_state.library if search_term.lower() in book["title"].lower() or search_term.lower() in book["author"].lower()]
        if matches:
            st.markdown("### 📋 Matching Books", unsafe_allow_html=True)
            for book in matches:
                st.markdown(f"<span style='color: #2ecc71'>{format_book(book)}</span>", unsafe_allow_html=True)
        else:
            st.info("ℹ️ No matching books found.")

def format_book(book):
    read_status = "✅ Read" if book["read"] else "⏳ Unread"
    return f"**Title**: {book['title']} | **Author**: {book['author']} | **Year**: {book['year']} | **Genre**: {book['genre']} | **Status**: {read_status}"

def display_all_books():
    st.subheader("📚 Your Library")
    st.markdown("Here’s your entire collection! 🌈", unsafe_allow_html=True)
    
    if not st.session_state.library:
        st.info("📭 Your library is empty. Add some books!")
    else:
        with st.expander("See all books", expanded=True):
            for book in st.session_state.library:
                st.markdown(f"<span style='color: #3498db'>{format_book(book)}</span>", unsafe_allow_html=True)

def display_statistics():
    st.subheader("📊 Library Statistics")
    st.markdown("Get a snapshot of your reading habits! 📈", unsafe_allow_html=True)
    
    total_books = len(st.session_state.library)
    if total_books == 0:
        st.info("📉 Your library is empty. No stats to show!")
    else:
        read_books = sum(1 for book in st.session_state.library if book["read"])
        percentage_read = (read_books / total_books) * 100
        st.markdown(f"**Total Books**: {total_books} 📚", unsafe_allow_html=True)
        st.markdown(f"**Books Read**: {read_books} ✅", unsafe_allow_html=True)
        st.markdown(f"**Percentage Read**: <span style='color: #e74c3c'>{percentage_read:.2f}%</span>", unsafe_allow_html=True)

def save_library():
    with open("library.txt", "w") as file:
        for book in st.session_state.library:
            file.write(f"{book['title']}|{book['author']}|{book['year']}|{book['genre']}|{book['read']}\n")

def load_library():
    if os.path.exists("library.txt"):
        with open("library.txt", "r") as file:
            st.session_state.library.clear()
            for line in file:
                title, author, year, genre, read = line.strip().split("|")
                book = {
                    "title": title,
                    "author": author,
                    "year": int(year),
                    "genre": genre,
                    "read": read == "True"
                }
                st.session_state.library.append(book)

if __name__ == "__main__":
    main()