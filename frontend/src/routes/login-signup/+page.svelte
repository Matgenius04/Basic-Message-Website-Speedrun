<script>

    import { goto } from "$app/navigation"
    import { Accounts } from "$lib/api/account.js"
    import Page from "$lib/components/page.svelte";

    let loginFields = {
        username: '',
        password: ''
    }
    let signupFields = {
        username: '',
        password: ''
    }
    const login = () => {
        if (Accounts.login(loginFields.username, loginFields.password) == "Success") goto("/chat") 
    }
    const signup = () => {
        if (Accounts.signup(signupFields.username, signupFields.password) == "Success") goto("/chat")
    }
</script>

<Page>
    <div class="flex-row">
        <div class="m-auto">
            <h2>Login</h2>
            <form class="flex-col">
                <div><input type="text" name="username" bind:value={loginFields.username}/></div>
                <div><input type="password" name="password" bind:value={loginFields.password}></div>
                <div><button name="submit" on:click={login}>Submit</button></div>
            </form>
        </div>
        <div class="m-auto">
            <h2>Signup</h2>
            <form class="flex-col">
                <div><input type="text" name="username" bind:value={signupFields.username}/></div>
                <div><input type="password" name="password" bind:value={signupFields.password}></div>
                <div><button name="submit" on:click={signup}>Submit</button></div>
            </form>
        </div>
    </div>
</Page>