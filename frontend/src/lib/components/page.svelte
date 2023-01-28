<script>
  import Navbar from "./navbar.svelte";
</script>

<main class="h-screen w-screen flex-row">
  <Navbar></Navbar>
  <slot></slot>
</main>