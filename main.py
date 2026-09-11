from src.database.db import init_db


def main():

    init_db()

    print(
        "AI Sentinel IDS/IPS initialized."
    )


if __name__ == "__main__":
    main()