def main():
    print("Hello from mirsad-ai!\n\n")

    def my_security_case(func):
        
        def wrapper():
            print("[BEFORE] Locking the room door...")
            func()
            print("[AFTER] Unlocking the door. Safe!\n\n")

        return wrapper



    @my_security_case
    def get_balance(account_number):
        print(f"Balance for {account_number} is $50")
    
    
    get_balance(10001)
    
if __name__ == "__main__":
    main()
