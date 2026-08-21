function toggleTheme(){

    document.body.classList.toggle("dark");

    const isDark = document.body.classList.contains("dark");

    localStorage.setItem("theme", isDark ? "dark" : "light");

}

window.onload = function(){

    if(localStorage.getItem("theme") === "dark"){

        document.body.classList.add("dark");

        document.getElementById("themeSwitch").checked = true;

    }

}