package com.unimap;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.web.servlet.support.SpringBootServletInitializer;
import java.sql.*;

import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.transaction.annotation.EnableTransactionManagement;

@SpringBootApplication(scanBasePackages = "com.unimap.zerohunger")
@EnableJpaRepositories
@EnableTransactionManagement

	public class ZerohungerApplication extends SpringBootServletInitializer  {
 
		public static void main(String[] args) throws SQLException {
			SpringApplicationBuilder app = new SpringApplicationBuilder(ZerohungerApplication.class);

			app.run();
		}
	 
		@Override
		protected SpringApplicationBuilder configure(SpringApplicationBuilder application) {
			return application.sources(ZerohungerApplication.class);
		}
	}
