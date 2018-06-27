<?php
require 'config.php';
?>
<html>
<head>
    <title><?php echo $blog_config['title'] ?></title>
    <link rel="stylesheet" href="<?php echo $env_config['root_path'];?>/views/element/element.css">
    <script src="<?php echo $env_config['root_path'];?>/views/element/vue.min.js"></script>
    <script src="<?php echo $env_config['root_path'];?>/views/element/element.js"></script>
</head>
<body>
    <div class="container" id="app">
        <el-card class="box-card">
            <div slot="header" class="clearfix">
                <span style="line-height: 36px;">{{ title }}</span>
            </div>
            <div class="text item" v-html="content"></div>
        </div>
    </div>
    <script>
        new Vue({
            el: '#app',
            data() {
                return {
                    title: "<?php echo $data['post']['title']; ?>"
                };
            },
            computed: {
                content() {
                    return `<?php echo $data['post']['content']; ?>`
                }
            }
        });
    </script>
</body>
</html>
