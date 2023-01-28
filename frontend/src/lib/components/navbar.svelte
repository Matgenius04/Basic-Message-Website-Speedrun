<script>
    import { Accounts } from '$lib/api/account.js'
    import { goto } from '$app/navigation'
    import { page } from '$app/stores'

    const loggedInStatus = Accounts.loggedIn();
    const logout = () => {
        Accounts.logout()
        goto("/")
    }
</script>


<nav class="flex-row w-full">
    <div id="logo" class="m-auto"></div>
    <div class="flex-row m-auto">
        <div class="link"><a href="/">Home</a></div>
        <div class="link"><a href="/chat">Chat</a></div>
    </div>
    <div class="flex-row m-auto">
        {#if loggedInStatus}
            <div class="link"><a on:click|once={logout}>Logout</a></div>
        {:else} 
            <div class="link"><a href="/login-signup">Login</a></div>
        {/if}
    </div>
</nav>

<style>
    .link {
        padding: 5px 1em;
    }
    a {
        font-weight: 500;
    }

</style>